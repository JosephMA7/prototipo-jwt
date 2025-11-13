from pymongo import MongoClient

# Conectar a MongoDB local
client = MongoClient("mongodb://localhost:27017/")
db = client["jwt_tesis"]
notas = db["notas"]

# Insertar una nota de ejemplo
nota = {
    "estudiante": "Mario",           # debe coincidir con username del estudiante
    "tarea": "Proyecto Final",
    "nota": 9.5,
    "observaciones": "Excelente trabajo"
}

notas.insert_one(nota)
print("Nota agregada exitosamente.")
