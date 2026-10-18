from pathlib import Path
from pypdf import PdfReader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
import chromadb
import hashlib
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# ==========================================
# STEP 1: LOAD PDF DOCUMENTS
# ==========================================

data_folder = Path("Data")

documents = []

seen_files = {}          # file hash -> first file name

for pdf_path in sorted(data_folder.glob("*.pdf")):

    # skip byte-identical copies such as "report (1).pdf"
    file_hash = hashlib.md5(pdf_path.read_bytes()).hexdigest()

    if file_hash in seen_files:
        print(f"Skipping duplicate file: {pdf_path.name} "
              f"(same as {seen_files[file_hash]})")
        continue

    seen_files[file_hash] = pdf_path.name

    reader = PdfReader(pdf_path)

    for page_number, page in enumerate(reader.pages):

        text = page.extract_text()

        if text:
            documents.append({
                "text": text,
                "source": pdf_path.name,
                "page": page_number + 1
            })

print("\n==========================================")
print("1. DOCUMENT LOADING")
print("==========================================")

print("Total pages loaded:", len(documents))


# ==========================================
# STEP 2: CHUNK DOCUMENTS
# ==========================================

splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200
)

chunks = []
seen_chunks = set()      # identical text from different files is stored once

for document in documents:

    split_texts = splitter.split_text(document["text"])

    for chunk_text in split_texts:

        chunk_key = hashlib.md5(chunk_text.strip().lower().encode()).hexdigest()

        if chunk_key in seen_chunks:
            continue

        seen_chunks.add(chunk_key)

        chunks.append({
            "text": chunk_text,
            "source": document["source"],
            "page": document["page"]
        })

print("\n==========================================")
print("2. DOCUMENT CHUNKING")
print("==========================================")

print("Total chunks created:", len(chunks))


# ==========================================
# STEP 3: CREATE EMBEDDINGS
# ==========================================

print("\n==========================================")
print("3. EMBEDDING GENERATION")
print("==========================================")

embedding_model = SentenceTransformer(
    "all-MiniLM-L6-v2"
)

texts = [chunk["text"] for chunk in chunks]

embeddings = embedding_model.encode(
    texts,
    show_progress_bar=True
)

print("Embeddings created:", len(embeddings))


# ==========================================
# STEP 4: CONNECT TO CHROMADB
# ==========================================

print("\n==========================================")
print("4. CHROMADB")
print("==========================================")

client = chromadb.PersistentClient(
    path="./chroma_db"
)

# ==========================================
# DELETE OLD DATABASE
# ==========================================

try:
    client.delete_collection(
        name="rag_knowledge_base"
    )
    print("Old knowledge base deleted.")
except Exception:
    print("No old knowledge base found.")


# ==========================================
# CREATE FRESH COLLECTION
# ==========================================

collection = client.create_collection(
    name="rag_knowledge_base"
)


# ==========================================
# STORE NEW CHUNKS
# ==========================================

collection.add(
    ids=[f"chunk_{i}" for i in range(len(chunks))],

    documents=texts,

    embeddings=embeddings.tolist(),

    metadatas=[
        {
            "source": chunk["source"],
            "page": chunk["page"]
        }
        for chunk in chunks
    ]
)

print("New chunks stored in ChromaDB:",
      collection.count())