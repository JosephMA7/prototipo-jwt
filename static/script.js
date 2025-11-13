async function login() {
  const user = document.getElementById("user").value;
  const pass = document.getElementById("pass").value;

  const res = await fetch("http://localhost:8000/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: user, password: pass })
  });

  const data = await res.json();
  if (!res.ok) {
    alert(data.detail || "Error al iniciar sesión");
    return;
  }

  // Guardar el token en el navegador
  localStorage.setItem("token", data.access_token);

  // Obtener los datos del usuario
  const info = await fetch("http://localhost:8000/me", {
    headers: { "Authorization": "Bearer " + data.access_token }
  });

  const usuario = await info.json();

  // Redirigir según el rol
  if (usuario.rol === "admin") {
    window.location.href = "/static/admin.html";
  } else if (usuario.rol === "estudiante") {
    window.location.href = "/static/estudiante.html";
  } else if (usuario.rol === "profesor") {
    window.location.href = "/static/profesor.html";
  } else {
    // En caso de un rol desconocido
    alert("Rol no reconocido");
  }
}


