import { useState } from "react";
import axios from "axios";

const RutasProtegidas = () => {
    const [rutaAdd, setRutaAdd] = useState("");
    const [rutaDelete, setRutaDelete] = useState("");
    const [message, setMessage] = useState("");

    const handleAdd = () => {
        axios.post("/rutas-protegidas/add", {
            path: rutaAdd
        }, {
            headers: { Authorization: `Token ${localStorage.getItem("token")}` }
        })
            .then(() => setMessage(" Ruta protegida añadida con éxito"))
            .catch(() => setMessage(" Error al añadir ruta"));
    };

    const handleDelete = () => {
        axios.post("/rutas-protegidas/delete", {
            path: rutaDelete
        }, {
            headers: { Authorization: `Token ${localStorage.getItem("token")}` }
        })
            .then(() => setMessage(" Ruta eliminada correctamente"))
            .catch(() => setMessage(" Error al eliminar ruta"));
    };

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">🧩 Rutas Protegidas</h2>

            {/* Añadir ruta */}
            <input
                type="text"
                className="w-full p-2 mb-2 rounded bg-gray-900 border border-gray-700"
                placeholder="Nueva ruta a proteger"
                value={rutaAdd}
                onChange={(e) => setRutaAdd(e.target.value)}
            />
            <button
                onClick={handleAdd}
                className="bg-green-600 px-4 py-2 rounded hover:bg-green-700 mb-4"
            >
                Añadir Ruta
            </button>

            {/* Eliminar ruta */}
            <input
                type="text"
                className="w-full p-2 mb-2 rounded bg-gray-900 border border-gray-700"
                placeholder="Ruta a eliminar"
                value={rutaDelete}
                onChange={(e) => setRutaDelete(e.target.value)}
            />
            <button
                onClick={handleDelete}
                className="bg-yellow-600 px-4 py-2 rounded hover:bg-yellow-700"
            >
                Eliminar Ruta
            </button>

            {message && <p className="mt-4 text-yellow-300">{message}</p>}
        </div>
    );
};

export default RutasProtegidas;
