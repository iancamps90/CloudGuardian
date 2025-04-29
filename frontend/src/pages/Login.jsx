import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { Link } from "react-router-dom";


const Login = () => {
    const [usuario, setUsuario] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const navigate = useNavigate();

    useEffect(() => {
        const token = localStorage.getItem("token");
        if (token) {
            navigate("/"); // redirige a home si ya está logueado
        }
    }, [navigate]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const res = await axios.post("/login/", {
                username: usuario,
                password: password,
            });

            localStorage.setItem("token", res.data.token);
            navigate("/");
        } catch (err) {
            setError("Usuario o contraseña incorrectos");
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-950 text-white">
            <form
                onSubmit={handleSubmit}
                className="bg-gray-900 p-8 rounded-lg shadow-lg w-full max-w-md"
            >
                <h2 className="text-2xl font-bold mb-6 text-center">Iniciar sesión</h2>

                <label className="block mb-2">Usuario</label>
                <input
                    type="text"
                    className="w-full p-2 mb-4 rounded bg-gray-800 border border-gray-700"
                    value={usuario}
                    onChange={(e) => setUsuario(e.target.value)}
                    required
                />

                <label className="block mb-2">Contraseña</label>
                <input
                    type="password"
                    className="w-full p-2 mb-6 rounded bg-gray-800 border border-gray-700"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                />

                {error && <p className="text-red-500 text-sm mb-4">{error}</p>}

                <button
                    type="submit"
                    className="w-full bg-blue-600 hover:bg-blue-700 py-2 px-4 rounded"
                >
                    Entrar
                </button>

                <p>¿No tienes cuenta? <Link to="/register">Regístrate aquí</Link></p>

            </form>
        </div>
    );
};

export default Login;
