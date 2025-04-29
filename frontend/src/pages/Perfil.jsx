// pages/Perfil.jsx (o crea uno nuevo si prefieres)
import { useState } from "react";
import axios from "axios";

const Perfil = () => {
    const [username, setUsername] = useState("");
    const [masterkey, setMasterkey] = useState("");
    const [message, setMessage] = useState("");

    const handleDelete = () => {
        axios.post("/user-delete", {
            username,
            masterkey
        }, {
            headers: { Authorization: `Token ${localStorage.getItem("token")}` }
        })
            .then(() => setMessage("Usuario eliminado"))
            .catch(() => setMessage("Error al eliminar usuario"));
    };

    return (
        <div className="p-6 max-w-md mx-auto">
            <h2 className="text-2xl font-bold mb-4">Eliminar usuario</h2>
            <input type="text" placeholder="Usuario a eliminar"
                value={username} onChange={(e) => setUsername(e.target.value)}
                className="w-full p-2 mb-2 rounded bg-gray-900 border border-gray-700" />
            <input type="password" placeholder="Masterkey"
                value={masterkey} onChange={(e) => setMasterkey(e.target.value)}
                className="w-full p-2 mb-2 rounded bg-gray-900 border border-gray-700" />
            <button
                onClick={handleDelete}
                className="bg-red-600 px-4 py-2 rounded hover:bg-red-700"
            >
                Eliminar usuario
            </button>
            {message && <p className="mt-2 text-yellow-300">{message}</p>}
        </div>
    );
};

export default Perfil;
