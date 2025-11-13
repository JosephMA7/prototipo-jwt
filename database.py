from pymongo import MongoClient

# Conexión local a MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["jwt_tesis"]
usuarios = db["usuarios"]
tareas = db["tareas"]
notas = db["notas"]  
refresh_tokens = db["refresh_tokens"]