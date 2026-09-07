import { Outlet, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import Nav from './Nav';
import Footer from './Footer';

export default function Layout() {
  const location = useLocation();

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  return (
    <>
      <Nav />
      <main className="page">
        <Outlet />
      </main>
      <Footer />
    </>
  );
}
