import { Outlet, NavLink } from "react-router-dom";
import Header from "../components/Header";
import Footer from "../components/Footer";

const MainLayout = () => {
    // lo q se reutiliza para cada página. Sirve para poner lo que NO cambia entre rutas
    return (
        <div className="min-h-screen flex flex-col bg-gray-950 text-white">
            <Header />
            <div className="flex flex-grow">
                {/* Sidebar */}
                <aside className="w-64 bg-gray-900 p-4 hidden md:block">
                    <nav className="space-y-2">
                        <NavLink
                            to="/"
                            className={({ isActive }) =>
                                `block p-2 rounded hover:bg-gray-700 ${isActive ? "bg-gray-800 font-bold" : ""
                                }`
                            }
                        >
                            Inicio
                        </NavLink>
                        <NavLink
                            to="/configuracion"
                            className={({ isActive }) =>
                                `block p-2 rounded hover:bg-gray-700 ${isActive ? "bg-gray-800 font-bold" : ""
                                }`
                            }
                        >
                            Configuración
                        </NavLink>
                        <NavLink
                            to="/ips-bloqueadas"
                            className={({ isActive }) =>
                                `block p-2 rounded hover:bg-gray-700 ${isActive ? "bg-gray-800 font-bold" : ""
                                }`
                            }
                        >
                            IPs Bloqueadas
                        </NavLink>
                        <NavLink
                            to="/rutas-protegidas"
                            className={({ isActive }) =>
                                `block p-2 rounded hover:bg-gray-700 ${isActive ? "bg-gray-800 font-bold" : ""
                                }`
                            }
                        >
                            Rutas Protegidas
                        </NavLink>
                    </nav>
                </aside>

                {/* Contenido principal */}
                <main className="flex-grow p-6">
                    <Outlet />
                </main>
            </div>
            <Footer />
        </div>
    );
};

export default MainLayout;
