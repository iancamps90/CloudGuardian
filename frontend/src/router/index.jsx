import { createBrowserRouter } from "react-router-dom";
import Home from "../pages/Home";
import MainLayout from "../layouts/MainLayout";
import Configuracion from "../pages/Configuracion";
import IpsBloqueadas from "../pages/IpsBloqueadas";
import RutasProtegidas from "../pages/RutasProtegidas";
import Login from "../pages/Login";
import PrivateRoute from "../components/PrivateRoute";
import Perfil from "../pages/Perfil";
import Register from '../pages/Register';


const router = createBrowserRouter([
    // Añade fuera del layout principal
    {
        path: "/login",
        element: <Login />,
    },
    {
        path: "/register", 
        element: <Register />,
    },
    {
        path: "/",
        element: <MainLayout />,
        children: [
            { path: "/home", element: <PrivateRoute><Home /></PrivateRoute> },
            { path: "/configuracion", element: <PrivateRoute><Configuracion /></PrivateRoute> },
            { path: "/ips-bloqueadas", element: <PrivateRoute><IpsBloqueadas /></PrivateRoute> },
            { path: "/rutas-protegidas", element: <PrivateRoute><RutasProtegidas /></PrivateRoute> },
            { path: "/perfil", element: <PrivateRoute><Perfil /></PrivateRoute> },
        ],
    },
]);

export default router;
