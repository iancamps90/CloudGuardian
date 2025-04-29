import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const Header = () => {
    const [logueado, setLogueado] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        const token = localStorage.getItem("token");
        setLogueado(!!token);
    }, []);

    const handleLogout = async () => {
        try {
            await fetch("/api/login/logout/", {
                method: "POST",
                headers: {
                    Authorization: `Token ${localStorage.getItem("token")}`,
                },
            });
        } catch (error) {
            console.warn("Error cerrando sesión", error);
        } finally {
            localStorage.removeItem("token");
            navigate("/login");
        }
    };

    return (
        <header className="bg-gray-900 p-4 shadow flex justify-between items-center">
            <h1
                className="text-xl font-semibold cursor-pointer"
                onClick={() => navigate("/")}
            >
                🛡️ CloudGuardian
            </h1>

            {logueado ? (
                <button
                    onClick={handleLogout}
                    className="bg-red-600 text-white px-4 py-1 rounded hover:bg-red-700"
                >
                    Cerrar sesión
                </button>
            ) : (
                <button
                    onClick={() => navigate("/login")}
                    className="bg-blue-600 text-white px-4 py-1 rounded hover:bg-blue-700"
                >
                    Iniciar sesión
                </button>
            )}
        </header>
    );
};

export default Header;
