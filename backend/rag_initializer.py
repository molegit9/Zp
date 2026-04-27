import pandas as pd
import chromadb
from chromadb.utils import embedding_functions
from tqdm import tqdm
import os
import sys

def init_vector_db(csv_path="merged_security_dataset.csv", sample_size=10000):
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found.")
        sys.exit(1)

    print(f"[1/4] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path).dropna(subset=['content'])
    print(f"[Info] Total loaded rows: {len(df)}")

    # 로컬 컴퓨터에서 모델이 수십만 개를 임베딩하려면 몇 시간이 소요될 수 있으므로, 
    # 졸업작품 시연을 위해 우선 1만 개만 균등하게 샘플링합니다. (필요시 sample_size 파라미터 조절)
    if len(df) > sample_size:
        print(f"[Info] To prevent hours of indexing, drawing a stratified sample of {sample_size} records...")
        # 라벨별 분포를 유지하며 샘플링
        df = df.groupby('label', group_keys=False).apply(lambda x: x.sample(min(len(x), sample_size // 5), random_state=42))
        print(f"[Info] Final sample size: {len(df)}")

    print("[2/4] Initializing Korean Embedding Model and ChromaDB...")
    # 한국어 스미싱 및 문서 파악에 최적화된 ko-sroberta-multitask 모델 사용
    emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="jhgan/ko-sroberta-multitask")
    
    # 디스크에 영구 저장되도록 PersistentClient 사용
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_or_create_collection(name="security_texts", embedding_function=emb_fn)

    print("[3/4] Vectorizing texts into the database (this might take a few minutes)...")
    batch_size = 500
    total_batches = (len(df) // batch_size) + 1

    for i in tqdm(range(total_batches), desc="Processing Batches"):
        batch_df = df.iloc[i * batch_size : (i + 1) * batch_size]
        if batch_df.empty:
            break
        
        # content, label, source 추출
        documents = batch_df['content'].astype(str).tolist()
        metadatas = [{"label": str(row['label']), "source": str(row.get('source', 'unknown'))} for _, row in batch_df.iterrows()]
        ids = [f"doc_{idx}" for idx in batch_df.index]
        
        collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

    print("[4/4] 🚀 Vector Database successfully initialized at ./chroma_db")
    print(f"Total documents inside DB: {collection.count()}")

if __name__ == "__main__":
    init_vector_db()
