import { useEffect, useState } from "react";

const Home = () => {
    const [usuario, setUsuario] = useState("");

    useEffect(() => {
        const token = localStorage.getItem("token");
        if (token) {
            // Simula obtener el nombre (en producción, haz un /me)
            setUsuario("Usuario Logueado");
        }
    }, []);

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold mb-4"> CloudGuardian Dashboard</h1>
            <p className="text-lg mb-6">Bienvenido {usuario && `, ${usuario}`} 👋</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-gray-800 p-4 rounded shadow">
                    <h2 className="text-xl font-bold mb-2"> Configuración</h2>
                    <p>Edita la configuración actual del firewall.</p>
                </div>
                <div className="bg-gray-800 p-4 rounded shadow">
                    <h2 className="text-xl font-bold mb-2"> IPs bloqueadas</h2>
                    <p>Gestiona IPs no autorizadas.</p>
                </div>
                <div className="bg-gray-800 p-4 rounded shadow">
                    <h2 className="text-xl font-bold mb-2"> Rutas protegidas</h2>
                    <p>Define rutas críticas protegidas.</p>
                </div>
                <div className="bg-gray-800 p-4 rounded shadow">
                    <h2 className="text-xl font-bold mb-2"> Registro/Login</h2>
                    <p>Gestiona el acceso de nuevos usuarios.</p>
                </div>
            </div>
        </div>
    );
};

export default Home;
