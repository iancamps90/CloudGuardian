import { useState } from "react";
import axios from "axios";

const IpsBloqueadas = () => {
    const [ipAdd, setIpAdd] = useState("");
    const [ipDelete, setIpDelete] = useState("");
    const [message, setMessage] = useState("");

    const handleAdd = () => {
        axios.post("/ips-bloqueadas/add", {
            allow: [],
            deny: [ipAdd]
        }, {
            headers: { Authorization: `Token ${localStorage.getItem("token")}` }
        })
            .then(() => setMessage(" IP bloqueada con éxito"))
            .catch(() => setMessage(" Error al bloquear IP"));
    };

    const handleDelete = () => {
        axios.post("/ips-bloqueadas/delete", {
            allow: [],
            deny: [ipDelete]
        }, {
            headers: { Authorization: `Token ${localStorage.getItem("token")}` }
        })
            .then(() => setMessage(" IP desbloqueada correctamente"))
            .catch(() => setMessage(" Error al desbloquear IP"));
    };

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4"> IPs Bloqueadas</h2>

            {/* Bloquear IP */}
            <input
                type="text"
                className="w-full p-2 mb-2 rounded bg-gray-900 border border-gray-700"
                placeholder="Nueva IP a bloquear"
                value={ipAdd}
                onChange={(e) => setIpAdd(e.target.value)}
            />
            <button
                onClick={handleAdd}
                className="bg-red-600 px-4 py-2 rounded hover:bg-red-700 mb-4"
            >
                Bloquear IP
            </button>

            {/* Desbloquear IP */}
            <input
                type="text"
                className="w-full p-2 mb-2 rounded bg-gray-900 border border-gray-700"
                placeholder="IP a desbloquear"
                value={ipDelete}
                onChange={(e) => setIpDelete(e.target.value)}
            />
            <button
                onClick={handleDelete}
                className="bg-yellow-600 px-4 py-2 rounded hover:bg-yellow-700"
            >
                Desbloquear IP
            </button>

            {message && <p className="mt-4 text-yellow-300">{message}</p>}
        </div>
    );
};

export default IpsBloqueadas;

