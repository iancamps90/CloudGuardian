import { useEffect, useState } from "react";
import axios from "axios";

const Configuracion = () => {
    const [config, setConfig] = useState("");
    const [message, setMessage] = useState("");

    useEffect(() => {
        axios.get("/api/config")
            .then(response => {
                const formatted = JSON.stringify(response.data, null, 2);
                setConfig(formatted);
            })
            .catch(error => {
                setMessage("Error al obtener configuración.");
                console.error(error);
            });
    }, []);

    const handleSave = () => {
        try {
            const parsedConfig = JSON.parse(config); // Validación
            axios.put("/api/config", parsedConfig)
                .then(res => {
                    if (res.data.message) setMessage(res.data.message);
                    else if (res.data.warning) setMessage(res.data.warning);
                })
                .catch(error => {
                    setMessage("Error al guardar.");
                    console.error(error);
                });
        } catch (err) {
            setMessage("JSON inválido.");
        }
    };

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">Configuración general</h2>
            <p className="mb-2">Aquí podrás ver y editar el <code>caddy.json</code> completo:</p>

            <textarea
                className="w-full h-96 p-4 rounded bg-gray-900 border border-gray-700 text-sm font-mono text-green-300"
                value={config}
                onChange={e => setConfig(e.target.value)}
            />

            <button
                className="mt-4 bg-blue-600 px-4 py-2 rounded hover:bg-blue-700"
                onClick={handleSave}
            >
                Guardar cambios
            </button>

            {message && <p className="mt-2 text-yellow-400">{message}</p>}
        </div>
    );
};

export default Configuracion;

