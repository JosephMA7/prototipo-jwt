from pymongo import MongoClient
import bcrypt
'''''
# URI de conexión a tu base de datos en MongoDB Atlas
uri = "mongodb+srv://josephjosue77:r5RxNn5lbear9TLN@clustertesis.yooccmi.mongodb.net/?retryWrites=true&w=majority&appName=ClusterTesis"
client = MongoClient(uri)

# Selección de base y colección
db = client["jwt_tesis"]
usuarios = db["usuarios"]
'''
# Conexión local
client = MongoClient("mongodb://localhost:27017/")
db = client["jwt_tesis"]
usuarios = db["usuarios"]

# Datos del usuario a insertar
username = input("Nombre de usuario: ")
password_plana = input("Contraseña: ")
rol = input("Rol (admin, profesor, estudiante): ")

# Cifrar la contraseña con bcrypt
password_cifrada = bcrypt.hashpw(password_plana.encode("utf-8"), bcrypt.gensalt())

# Crear documento
nuevo_usuario = {
    "username": username,
    "password": password_cifrada,
    "role": rol

}


# Insertar en la colección
usuarios.insert_one(nuevo_usuario)

print("Usuario insertado correctamente.")
