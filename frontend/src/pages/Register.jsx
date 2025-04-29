import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';



export default function Register() {
    const [username, setUsername] = useState('');
    const [password1, setPassword1] = useState('');
    const [password2, setPassword2] = useState('');
    const [message, setMessage] = useState('');
    const navigate = useNavigate();

    const handleRegister = (e) => {
        e.preventDefault();

        if (password1 !== password2) {
            setMessage("Las contraseñas no coinciden");
            return;
        }

        axios.post('/register', {
            username,
            password1,
            password2
        })
            .then(res => {
                setMessage('Registro exitoso');
                setTimeout(() => navigate("/login"), 1500);
            })
            .catch(err => {
                const detail = err.response?.data?.non_field_errors?.[0] || err.response?.data?.password1?.[0] || "Error en el registro";
                setMessage(detail);
            });
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-950 text-white">
            <form
                onSubmit={handleRegister}
                className="bg-gray-900 p-8 rounded-lg shadow-lg w-full max-w-md"
            >
                <h2 className="text-2xl font-bold mb-6 text-center">Registro</h2>

                <label className="block mb-2">Usuario</label>
                <input
                    type="text"
                    className="w-full p-2 mb-4 rounded bg-gray-800 border border-gray-700"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                />

                <label className="block mb-2">Contraseña</label>
                <input
                    type="password"
                    className="w-full p-2 mb-4 rounded bg-gray-800 border border-gray-700"
                    value={password1}
                    onChange={(e) => setPassword1(e.target.value)}
                    required
                />

                <label className="block mb-2">Repetir contraseña</label>
                <input
                    type="password"
                    className="w-full p-2 mb-6 rounded bg-gray-800 border border-gray-700"
                    value={password2}
                    onChange={(e) => setPassword2(e.target.value)}
                    required
                />

                {message && <p className="text-red-500 text-sm mb-4">{message}</p>}

                <button
                    type="submit"
                    className="w-full bg-green-600 hover:bg-green-700 py-2 px-4 rounded"
                >
                    Registrarse
                </button>
            </form>
        </div>
    );
}
