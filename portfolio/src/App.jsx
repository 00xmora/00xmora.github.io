import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Home from './pages/Home';
import About from './components/About';
import Services from './components/Services';
import Experience from './components/Experience';
import SkillsCerts from './components/SkillsCerts';
import Contact from './components/Contact';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
        <Route path="/services" element={<Services />} />
        <Route path="/experience" element={<Experience />} />
        <Route path="/skills" element={<SkillsCerts />} />
        <Route path="/contact" element={<Contact />} />
        <Route path="*" element={<Home />} />
      </Route>
    </Routes>
  );
}
