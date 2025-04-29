# ☁️🛡️ CLOUD GUARDIAN — El escudo que nunca duerme

**CloudGuardian** es una plataforma full stack diseñada para ofrecer control, protección y visibilidad total sobre el tráfico web. Inspirado en soluciones como Cloudflare, permite gestionar reglas de firewall, monitorizar logs y mantener la nube segura 24/7.

---




---

## 🚀 Funcionalidades principales

- 🔒 Reglas de firewall (por IP, país o tipo de tráfico)
- 📄 Visualización de logs en tiempo real
- ⚙️ Panel de configuración dinámico (con edición JSON vía interfaz)
- 🧠 Estado del sistema: CPU, RAM, Disco, Red
- 👤 Gestión de usuarios y autenticación básica
- 📊 Dashboard con métricas y estadísticas
- 🔐 Seguridad: despliegue con Caddy, Docker y claves SSH

---

## 🧪 Tecnologías utilizadas

### 🖥️ Frontend
- React.js (con Vite)
- TailwindCSS (modo oscuro 🔴🖤)
- React Router Dom


### 🧠 Backend
- Django + Django REST Framework
- Mysql
- Edición de configuración vía panel

### 🔧 DevOps
- Docker & Docker Compose
- GitHub Actions (CI/CD)
- Caddy Server como reverse proxy con JSON dinámico
- Usuario `despliegue` O IAN con llave SSH personalizada

---

## 📁 Estructura del proyecto

```
root/
├── frontend/        ← React con Vite, rutas, layouts
├── backend/         ← Django + API REST + seguridad
├── deploy/          ← Dockerfile, Caddy config, entrypoints
└── README.md
```

---

```

Accede a: [http://localhost:8000](http://localhost:8000) o IP en cloud.

---



---


