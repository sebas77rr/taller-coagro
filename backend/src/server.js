import dotenv from "dotenv";
import express from "express";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import path from "path";
import fs from "fs";
import multer from "multer";
import { fileURLToPath } from "url";

// ---------------------------------------------------------
// __dirname real (ESM safe)
// ---------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------
// Cargar .env desde rutas posibles (Hostinger cambia cwd)
// ---------------------------------------------------------
dotenv.config({ path: path.resolve(__dirname, "..", ".env") });
dotenv.config({ path: path.resolve(process.cwd(), ".env") });
dotenv.config();

// ---------------------------------------------------------
// Entorno
// ---------------------------------------------------------
const IS_PROD =
  process.env.NODE_ENV === "production" ||
  process.env.NODE_ENV === "prod" ||
  process.env.HOSTINGER === "1";

// Sanitización defensiva
const sanitize = (v = "") =>
  String(v)
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .replace(/\s+/g, "");

process.env.DATABASE_URL = sanitize(
  process.env.DATABASE_URL ||
    process.env.DATABASE_URL_ ||
    process.env.DATABASE_URL_FALLBACK ||
    ""
);

process.env.JWT_SECRET = sanitize(process.env.JWT_SECRET || "");

// ---------------------------------------------------------
// Uploads (server.js en /src → uploads en /uploads)
// ---------------------------------------------------------
const UPLOADS_DIR = path.resolve(__dirname, "..", "uploads");
const UPLOADS_ORDENES_DIR = path.join(UPLOADS_DIR, "ordenes");

try {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  fs.mkdirSync(UPLOADS_ORDENES_DIR, { recursive: true });
} catch (e) {
  console.error("❌ No se pudo crear uploads:", e);
}

// ---------------------------------------------------------
// Reporte de entorno (debug real)
// ---------------------------------------------------------
const envReport = () => {
  const v = process.env.DATABASE_URL || "";
  return {
    NODE_ENV: process.env.NODE_ENV || null,
    isProd: IS_PROD,
    has_DATABASE_URL: !!v,
    DATABASE_URL_len: v.length,
    DATABASE_URL_preview: v ? v.slice(0, 12) + "..." : null,
    has_JWT_SECRET: !!process.env.JWT_SECRET,
    cwd: process.cwd(),
    __dirname,
    UPLOADS_DIR,
    uploadsExists: fs.existsSync(UPLOADS_DIR),
    ordenesDir: UPLOADS_ORDENES_DIR,
    ordenesExists: fs.existsSync(UPLOADS_ORDENES_DIR),
  };
};

console.log("ENV CHECK:", envReport());

// ---------------------------------------------------------
// Prisma: conexión única (sin reconectar en cada request)
// ---------------------------------------------------------
let prisma = null;
let prismaReady = false;
let prismaLastError = null;

async function initPrisma() {
  if (!process.env.DATABASE_URL) {
    prismaLastError = "DATABASE_URL vacío";
    prismaReady = false;
    console.error("❌ Prisma NO inicializa: DATABASE_URL vacío.");
    return;
  }

  try {
    prisma = new PrismaClient();
    await prisma.$connect();
    prismaReady = true;
    prismaLastError = null;
    console.log("✅ DB connected (Prisma)");
  } catch (e) {
    prismaReady = false;
    prismaLastError = e?.message || String(e);
    console.error("❌ DB connect failed:", prismaLastError);
  }
}

// Inicializa al boot
await initPrisma();

// ---------------------------------------------------------
// Evita procesos zombie + cierre limpio
// ---------------------------------------------------------
process.on("unhandledRejection", (err) =>
  console.error("❌ UnhandledRejection:", err)
);
process.on("uncaughtException", (err) =>
  console.error("❌ UncaughtException:", err)
);

process.on("SIGTERM", async () => {
  try {
    if (prisma) await prisma.$disconnect();
  } catch {}
  process.exit(0);
});

process.on("SIGINT", async () => {
  try {
    if (prisma) await prisma.$disconnect();
  } catch {}
  process.exit(0);
});

// ---------------------------------------------------------
// Express base
// ---------------------------------------------------------
const app = express();
app.set("trust proxy", 1);

// ---------------------------------------------------------
// CORS + Preflight (antes de rutas)
// ---------------------------------------------------------
const ALLOWED_ORIGINS = [
  "https://greenyellow-ant-906707.hostingersite.com",
  "https://indigo-lark-430359.hostingersite.com",
  "http://localhost:5173",
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// ---------------------------------------------------------
// Parsers
// ---------------------------------------------------------
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------
// Static uploads (evita ORB)
// ---------------------------------------------------------
app.use(
  "/uploads",
  (req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    next();
  },
  express.static(UPLOADS_DIR)
);

// ---------------------------------------------------------
// Health / Env
// ---------------------------------------------------------
app.get("/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get("/__envcheck", (req, res) => res.json(envReport()));

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    db: prismaReady ? "up" : "down",
    prismaReady,
    prismaLastError,
  });
});

// Un solo root (sin duplicados)
app.get("/", (req, res) =>
  res.json({ ok: true, message: "API Taller Coagro online" })
);

app.get("/whoami", (req, res) => res.send("SERVER.JS ACTIVO ✅"));

// dbcheck SIN reconectar (esto te quita crashes)
app.get("/dbcheck", async (req, res) => {
  try {
    if (!prisma || !prismaReady) {
      return res.status(503).json({
        ok: false,
        db: "down",
        error: prismaLastError || "Prisma no listo",
      });
    }

    await prisma.$queryRaw`SELECT 1`;
    return res.json({ ok: true, db: "up" });
  } catch (e) {
    prismaReady = false;
    prismaLastError = e?.message || String(e);
    return res
      .status(500)
      .json({ ok: false, db: "down", error: prismaLastError });
  }
});

// ---------------------------------------------------------
// Multer (evidencias)
// ---------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 },
});

/* =========================================================
   Helpers: Eventos (auditoría)
========================================================= */
async function logOrdenEvento({ ordenId, tipo, detalle, usuarioId }) {
  try {
    if (!prisma || !prismaReady) return;
    await prisma.ordenEvento.create({
      data: {
        ordenId,
        tipo,
        detalle: detalle || null,
        usuarioId: usuarioId ?? null,
      },
    });
  } catch (e) {
    console.error("No se pudo registrar evento:", e?.message || e);
  }
}

/* =========================================================
   Middlewares: Auth + Roles
========================================================= */
const verificarToken = (req, res, next) => {
  if (!prisma || !prismaReady) {
    return res.status(503).json({
      error: "DB no disponible",
      detail: prismaLastError || "Prisma no inicializó correctamente",
    });
  }

  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ error: "Token no proporcionado" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token inválido" });

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({ error: "JWT_SECRET no configurado" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded; // {id, rol, sedeId}
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
};

const soloAdmin = (req, res, next) => {
  if (req.usuario?.rol !== "ADMIN") {
    return res.status(403).json({ error: "Acceso solo para administradores" });
  }
  next();
};

const soloAdminOJefeTaller = (req, res, next) => {
  const rol = req.usuario?.rol;
  if (rol === "ADMIN" || rol === "JEFE_TALLER") return next();
  return res
    .status(403)
    .json({ error: "Acceso solo para administrador o jefe de taller" });
};

const adminJefeOTecnico = (req, res, next) => {
  const rol = req.usuario?.rol;
  if (rol === "ADMIN" || rol === "JEFE_TALLER" || rol === "TECNICO")
    return next();
  return res.status(403).json({ error: "No tienes permisos" });
};

/* =========================================================
   Rutas: Auth
========================================================= */
// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    if (!prisma || !prismaReady) {
      return res.status(503).json({
        error: "DB no disponible",
        detail: prismaLastError || "Prisma no listo",
      });
    }

    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email y password son obligatorios" });
    }

    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario)
      return res.status(401).json({ error: "Credenciales inválidas" });

    if (!usuario.password) {
      return res.status(500).json({
        error: "Usuario sin password en BD (null). Revisa seed/import.",
      });
    }

    const passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido)
      return res.status(401).json({ error: "Credenciales inválidas" });

    const token = jwt.sign(
      { id: usuario.id, rol: usuario.rol, sedeId: usuario.sedeId },
      process.env.JWT_SECRET,
      { expiresIn: "5h" }
    );

    return res.json({
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
        sedeId: usuario.sedeId,
      },
    });
  } catch (error) {
    console.error("Error login:", error?.message || error);
    return res.status(500).json({
      error: "Error en login",
      detail: error?.message || String(error),
    });
  }
});

/* =========================================================
   Equipos
========================================================= */
// Crear equipo (ADMIN / JEFE_TALLER)
app.post(
  "/api/equipos",
  verificarToken,
  soloAdminOJefeTaller,
  async (req, res) => {
    try {
      const { clienteId, marca, modelo, serial, descripcion } = req.body;

      if (!clienteId || !marca || !modelo || !serial) {
        return res.status(400).json({
          error: "clienteId, marca, modelo y serial son obligatorios",
        });
      }

      const clienteIdNum = Number(clienteId);
      if (Number.isNaN(clienteIdNum)) {
        return res.status(400).json({ error: "clienteId inválido" });
      }

      const cliente = await prisma.cliente.findUnique({
        where: { id: clienteIdNum },
      });
      if (!cliente)
        return res.status(404).json({ error: "Cliente no encontrado" });

      const equipo = await prisma.equipo.create({
        data: {
          clienteId: clienteIdNum,
          marca: String(marca).trim(),
          modelo: String(modelo).trim(),
          serial: String(serial).trim(),
          descripcion: descripcion ? String(descripcion) : "",
        },
        include: { cliente: true },
      });

      res.status(201).json(equipo);
    } catch (error) {
      console.error("Error creando equipo:", error?.message || error);
      res.status(500).json({ error: "Error creando equipo" });
    }
  }
);

// Listar equipos
app.get("/api/equipos", verificarToken, async (req, res) => {
  try {
    const equipos = await prisma.equipo.findMany({
      include: { cliente: true },
      orderBy: { id: "desc" },
    });
    res.json(equipos);
  } catch (error) {
    console.error("Error listando equipos:", error?.message || error);
    res.status(500).json({ error: "Error listando equipos" });
  }
});

/* =========================================================
   Órdenes
========================================================= */
// Crear orden
app.post("/api/ordenes", verificarToken, async (req, res) => {
  try {
    const {
      sedeId,
      clienteId,
      equipoId,
      tipoIngreso,
      motivoIngreso,
      tecnicoId,
    } = req.body;

    if (!sedeId || !clienteId || !equipoId || !tipoIngreso || !motivoIngreso) {
      return res.status(400).json({
        error: "Faltan datos obligatorios",
        detalle: { sedeId, clienteId, equipoId, tipoIngreso, motivoIngreso },
      });
    }

    const tiposValidos = ["GARANTIA", "MANTENIMIENTO", "REPARACION"];
    if (!tiposValidos.includes(tipoIngreso)) {
      return res.status(400).json({
        error: "tipoIngreso inválido",
        permitido: tiposValidos,
        recibido: tipoIngreso,
      });
    }

    const sedeIdNum = Number(sedeId);
    const clienteIdNum = Number(clienteId);
    const equipoIdNum = Number(equipoId);
    const tecnicoIdNum = tecnicoId ? Number(tecnicoId) : null;

    if (
      Number.isNaN(sedeIdNum) ||
      Number.isNaN(clienteIdNum) ||
      Number.isNaN(equipoIdNum)
    ) {
      return res
        .status(400)
        .json({ error: "IDs inválidos, deben ser numéricos" });
    }

    const codigo = `OS-${sedeIdNum}-${Date.now()}`;

    const orden = await prisma.ordenServicio.create({
      data: {
        codigo,
        sedeId: sedeIdNum,
        clienteId: clienteIdNum,
        equipoId: equipoIdNum,
        tipoIngreso,
        motivoIngreso: String(motivoIngreso).trim(),
        tecnicoId: tecnicoIdNum,
      },
      include: {
        sede: true,
        cliente: true,
        equipo: true,
        tecnicoAsignado: true,
      },
    });

    await logOrdenEvento({
      ordenId: orden.id,
      tipo: "ORDEN_CREADA",
      detalle: `Ingreso: ${tipoIngreso}. Motivo: ${String(
        motivoIngreso
      ).trim()}`,
      usuarioId: req.usuario?.id,
    });

    res.status(201).json(orden);
  } catch (error) {
    console.error("Error creando orden:", error?.message || error);
    res.status(500).json({ error: "Error creando orden de servicio" });
  }
});

// Listar órdenes
app.get("/api/ordenes", verificarToken, async (req, res) => {
  try {
    const { sedeId, estado } = req.query;

    const where = {
      sedeId: req.usuario.rol === "ADMIN" ? undefined : req.usuario.sedeId,
    };

    if (sedeId) {
      const sedeIdNum = Number(sedeId);
      if (!Number.isNaN(sedeIdNum)) where.sedeId = sedeIdNum;
    }

    if (estado) where.estado = estado;

    const ordenes = await prisma.ordenServicio.findMany({
      where,
      include: {
        sede: true,
        cliente: true,
        equipo: true,
        tecnicoAsignado: true,
      },
      orderBy: { fechaIngreso: "desc" },
    });

    res.json(ordenes);
  } catch (error) {
    console.error("Error listando órdenes:", error?.message || error);
    res.status(500).json({ error: "Error listando órdenes" });
  }
});

// Detalle orden
app.get("/api/ordenes/:id", verificarToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

    const orden = await prisma.ordenServicio.findUnique({
      where: { id },
      include: {
        sede: true,
        cliente: true,
        equipo: true,
        tecnicoAsignado: true,
        manoObra: true,
        repuestos: { include: { repuesto: true } },
      },
    });

    if (!orden) return res.status(404).json({ error: "Orden no encontrada" });
    res.json(orden);
  } catch (error) {
    console.error("Error obteniendo orden:", error?.message || error);
    res.status(500).json({ error: "Error obteniendo orden" });
  }
});

// Cambiar estado orden
app.patch("/api/ordenes/:id/estado", verificarToken, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { estado } = req.body;

    if (Number.isNaN(id)) return res.status(400).json({ error: "ID inválido" });

    const estadosValidos = [
      "ABIERTA",
      "EN_PROCESO",
      "ESPERANDO_REPUESTO",
      "FINALIZADA",
      "ENTREGADA",
    ];
    if (!estado || !estadosValidos.includes(estado)) {
      return res
        .status(400)
        .json({ error: "Estado inválido", permitido: estadosValidos });
    }

    const existe = await prisma.ordenServicio.findUnique({ where: { id } });
    if (!existe) return res.status(404).json({ error: "Orden no encontrada" });

    const estadoAntes = existe.estado;

    const ordenActualizada = await prisma.ordenServicio.update({
      where: { id },
      data: {
        estado,
        fechaSalida:
          estado === "ENTREGADA" || estado === "FINALIZADA"
            ? new Date()
            : existe.fechaSalida,
      },
    });

    await logOrdenEvento({
      ordenId: id,
      tipo: "ESTADO_CAMBIADO",
      detalle: `${estadoAntes} → ${estado}`,
      usuarioId: req.usuario?.id,
    });

    res.json(ordenActualizada);
  } catch (error) {
    console.error("Error actualizando estado:", error?.message || error);
    res.status(500).json({ error: "Error actualizando estado de orden" });
  }
});

// Asignar técnico (solo ADMIN/JEFE)
app.patch(
  "/api/ordenes/:id/tecnico",
  verificarToken,
  soloAdminOJefeTaller,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { tecnicoId } = req.body;

      if (Number.isNaN(id))
        return res.status(400).json({ error: "ID inválido" });

      const tecnicoIdNum = tecnicoId === null ? null : Number(tecnicoId);
      if (tecnicoId !== null && Number.isNaN(tecnicoIdNum)) {
        return res.status(400).json({ error: "tecnicoId inválido" });
      }

      const orden = await prisma.ordenServicio.findUnique({ where: { id } });
      if (!orden) return res.status(404).json({ error: "Orden no encontrada" });

      if (tecnicoIdNum !== null) {
        const tecnico = await prisma.usuario.findUnique({
          where: { id: tecnicoIdNum },
        });
        if (!tecnico)
          return res.status(404).json({ error: "Técnico no encontrado" });
        if (tecnico.rol !== "TECNICO") {
          return res
            .status(400)
            .json({ error: "El usuario seleccionado no es técnico" });
        }
      }

      const upd = await prisma.ordenServicio.update({
        where: { id },
        data: { tecnicoId: tecnicoIdNum },
        include: { tecnicoAsignado: true },
      });

      await logOrdenEvento({
        ordenId: id,
        tipo: "TECNICO_ASIGNADO",
        detalle: tecnicoIdNum
          ? `Técnico asignado ID: ${tecnicoIdNum}`
          : "Técnico desasignado",
        usuarioId: req.usuario?.id,
      });

      res.json(upd);
    } catch (error) {
      console.error("Error asignando técnico:", error?.message || error);
      res.status(500).json({ error: "Error asignando técnico" });
    }
  }
);

// Listar técnicos
app.get("/api/tecnicos", verificarToken, async (req, res) => {
  try {
    const tecnicos = await prisma.usuario.findMany({
      where: { rol: "TECNICO" },
      select: { id: true, nombre: true, email: true, sedeId: true },
      orderBy: { nombre: "asc" },
    });
    res.json(tecnicos);
  } catch (error) {
    console.error("Error listando técnicos:", error?.message || error);
    res.status(500).json({ error: "Error listando técnicos" });
  }
});

/* =========================================================
   Mano de obra
========================================================= */
app.post("/api/ordenes/:id/mano-obra", verificarToken, async (req, res) => {
  try {
    const ordenId = Number(req.params.id);
    const { descripcion, horas } = req.body;

    if (Number.isNaN(ordenId))
      return res.status(400).json({ error: "ID de orden inválido" });
    if (!descripcion || horas == null) {
      return res
        .status(400)
        .json({
          error: "Faltan datos obligatorios",
          detalle: { descripcion, horas },
        });
    }

    const horasNum = Number(horas);
    if (Number.isNaN(horasNum) || horasNum <= 0) {
      return res.status(400).json({ error: "Horas inválidas (mayor a 0)" });
    }

    const orden = await prisma.ordenServicio.findUnique({
      where: { id: ordenId },
    });
    if (!orden) return res.status(404).json({ error: "Orden no encontrada" });

    const manoObra = await prisma.ordenManoObra.create({
      data: {
        ordenId,
        descripcionTrabajo: String(descripcion).trim(),
        horas: horasNum,
        costoHora: 0,
        subtotal: 0,
      },
    });

    await logOrdenEvento({
      ordenId,
      tipo: "MANO_OBRA_AGREGADA",
      detalle: `${String(descripcion).trim()} · ${horasNum} horas`,
      usuarioId: req.usuario?.id,
    });

    res.status(201).json(manoObra);
  } catch (error) {
    console.error("Error agregando mano de obra:", error?.message || error);
    res.status(500).json({ error: "Error agregando mano de obra" });
  }
});

async function assertOrdenEditable(ordenId) {
  if (!prisma || !prismaReady) {
    return {
      ok: false,
      status: 503,
      error: "DB no disponible (Prisma no listo)",
    };
  }

  const orden = await prisma.ordenServicio.findUnique({
    where: { id: ordenId },
  });
  if (!orden) return { ok: false, status: 404, error: "Orden no encontrada" };

  const cerrada = orden.estado === "FINALIZADA" || orden.estado === "ENTREGADA";
  if (cerrada)
    return { ok: false, status: 409, error: "Orden cerrada: solo lectura" };

  return { ok: true, orden };
}

app.get("/api/ordenes/:id/mano-obra", verificarToken, async (req, res) => {
  try {
    const ordenId = Number(req.params.id);
    if (Number.isNaN(ordenId))
      return res.status(400).json({ error: "ID inválido" });

    const items = await prisma.ordenManoObra.findMany({
      where: { ordenId },
      orderBy: { id: "desc" },
    });

    res.json(items);
  } catch (error) {
    console.error("Error listando mano de obra:", error?.message || error);
    res.status(500).json({ error: "Error listando mano de obra" });
  }
});

/* =========================================================
   Repuestos (catálogo + asignación a orden)
========================================================= */
// Buscar repuestos
app.get("/api/repuestos", verificarToken, async (req, res) => {
  try {
    const search = (req.query.search || "").toString().trim();

    const where = search
      ? {
          OR: [
            { codigo: { contains: search, mode: "insensitive" } },
            { descripcion: { contains: search, mode: "insensitive" } },
          ],
        }
      : {};

    const repuestos = await prisma.repuesto.findMany({
      where,
      orderBy: { id: "asc" },
      take: 50,
    });

    res.json(repuestos);
  } catch (error) {
    console.error("Error listando repuestos:", error?.message || error);
    res.status(500).json({ error: "Error listando repuestos" });
  }
});

// Crear repuesto (ADMIN/JEFE/TECNICO)
app.post(
  "/api/repuestos",
  verificarToken,
  adminJefeOTecnico,
  async (req, res) => {
    try {
      const { codigo, descripcion, costo, stockGlobal } = req.body;

      if (!codigo || !descripcion) {
        return res
          .status(400)
          .json({ error: "codigo y descripcion son obligatorios" });
      }

      const codigoClean = String(codigo).trim();

      const existe = await prisma.repuesto.findUnique({
        where: { codigo: codigoClean },
      });
      if (existe) {
        return res
          .status(409)
          .json({
            error: "Ya existe un repuesto con ese código",
            repuesto: existe,
          });
      }

      const nuevo = await prisma.repuesto.create({
        data: {
          codigo: codigoClean,
          descripcion: String(descripcion).trim(),
          costo: Number(costo) || 0,
          stockGlobal: Number(stockGlobal) || 0,
        },
      });

      res.status(201).json(nuevo);
    } catch (error) {
      console.error("Error creando repuesto:", error?.message || error);
      res.status(500).json({ error: "Error creando repuesto" });
    }
  }
);

// Agregar repuesto a orden
app.post("/api/ordenes/:id/repuestos", verificarToken, async (req, res) => {
  try {
    const ordenId = Number(req.params.id);
    const { repuestoId, cantidad, esGarantia } = req.body;

    if (Number.isNaN(ordenId))
      return res.status(400).json({ error: "ID de orden inválido" });

    const repuestoIdNum = Number(repuestoId);
    const cantidadNum = Number(cantidad);

    if (
      Number.isNaN(repuestoIdNum) ||
      Number.isNaN(cantidadNum) ||
      cantidadNum <= 0
    ) {
      return res
        .status(400)
        .json({ error: "repuestoId y cantidad válidos son obligatorios" });
    }

    const orden = await prisma.ordenServicio.findUnique({
      where: { id: ordenId },
    });
    if (!orden) return res.status(404).json({ error: "Orden no encontrada" });

    const repuesto = await prisma.repuesto.findUnique({
      where: { id: repuestoIdNum },
    });
    if (!repuesto)
      return res.status(404).json({ error: "Repuesto no encontrado" });

    const garantia = Boolean(esGarantia);
    const costoUnitario = garantia ? 0 : repuesto.costo;
    const subtotal = costoUnitario * cantidadNum;

    const repuestoOrden = await prisma.ordenRepuesto.create({
      data: {
        ordenId,
        repuestoId: repuestoIdNum,
        cantidad: cantidadNum,
        costoUnitario,
        esGarantia: garantia,
        subtotal,
      },
      include: { repuesto: true },
    });

    await logOrdenEvento({
      ordenId,
      tipo: "REPUESTO_AGREGADO",
      detalle: `${repuesto.codigo} · ${
        repuesto.descripcion
      } · Cant: ${cantidadNum}${garantia ? " (GARANTÍA)" : ""}`,
      usuarioId: req.usuario?.id,
    });

    res.status(201).json(repuestoOrden);
  } catch (error) {
    console.error("Error agregando repuesto a orden:", error?.message || error);
    res.status(500).json({ error: "Error agregando repuesto a la orden" });
  }
});

// Listar repuestos de orden
app.get("/api/ordenes/:id/repuestos", verificarToken, async (req, res) => {
  try {
    const ordenId = Number(req.params.id);
    if (Number.isNaN(ordenId))
      return res.status(400).json({ error: "ID inválido" });

    const repuestos = await prisma.ordenRepuesto.findMany({
      where: { ordenId },
      include: { repuesto: true },
      orderBy: { id: "desc" },
    });

    res.json(repuestos);
  } catch (error) {
    console.error("Error listando repuestos:", error?.message || error);
    res.status(500).json({ error: "Error listando repuestos" });
  }
});

/* =========================================================
   Eventos: Timeline de la orden
========================================================= */
app.get("/api/ordenes/:id/eventos", verificarToken, async (req, res) => {
  try {
    const ordenId = Number(req.params.id);
    if (Number.isNaN(ordenId))
      return res.status(400).json({ error: "ID inválido" });

    const eventos = await prisma.ordenEvento.findMany({
      where: { ordenId },
      orderBy: { createdAt: "desc" },
    });

    res.json(eventos);
  } catch (error) {
    console.error("Error listando eventos:", error?.message || error);
    res.status(500).json({ error: "Error listando eventos" });
  }
});

/* =========================================================
   Usuarios (ADMIN)
========================================================= */
app.post("/api/usuarios", verificarToken, soloAdmin, async (req, res) => {
  try {
    const { nombre, email, password, rol, sedeId } = req.body;

    if (!nombre || !email || !password || !rol) {
      return res
        .status(400)
        .json({ error: "Nombre, email, password y rol son obligatorios" });
    }

    const rolesValidos = ["ADMIN", "JEFE_TALLER", "TECNICO"];
    if (!rolesValidos.includes(rol)) {
      return res
        .status(400)
        .json({
          error: "Rol inválido",
          permitido: rolesValidos,
          recibido: rol,
        });
    }

    const existe = await prisma.usuario.findUnique({ where: { email } });
    if (existe)
      return res
        .status(409)
        .json({ error: "Ya existe un usuario con ese email" });

    const hash = await bcrypt.hash(password, 10);

    const sedeIdNum = sedeId ? Number(sedeId) : null;
    if (sedeId && Number.isNaN(sedeIdNum))
      return res.status(400).json({ error: "sedeId inválido" });

    const nuevo = await prisma.usuario.create({
      data: { nombre, email, password: hash, rol, sedeId: sedeIdNum },
      select: { id: true, nombre: true, email: true, rol: true, sedeId: true },
    });

    res.status(201).json(nuevo);
  } catch (error) {
    console.error("Error creando usuario:", error?.message || error);
    res.status(500).json({ error: "Error creando usuario" });
  }
});

app.get("/api/usuarios", verificarToken, soloAdmin, async (req, res) => {
  try {
    const usuarios = await prisma.usuario.findMany({
      orderBy: { id: "asc" },
      select: { id: true, nombre: true, email: true, rol: true, sedeId: true },
    });

    res.json(usuarios);
  } catch (error) {
    console.error("Error listando usuarios:", error?.message || error);
    res.status(500).json({ error: "Error listando usuarios" });
  }
});

/* =========================================================
   Evidencias
========================================================= */
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function safeExt(mimetype) {
  if (mimetype === "image/jpeg") return "jpg";
  if (mimetype === "image/png") return "png";
  if (mimetype === "image/webp") return "webp";
  if (mimetype === "video/mp4") return "mp4";
  if (mimetype === "video/webm") return "webm";
  return null;
}

app.post(
  "/api/ordenes/:ordenId/evidencias",
  verificarToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const ordenId = Number(req.params.ordenId);
      if (Number.isNaN(ordenId))
        return res.status(400).json({ error: "ordenId inválido" });

      const orden = await prisma.ordenServicio.findUnique({
        where: { id: ordenId },
      });
      if (!orden) return res.status(404).json({ error: "Orden no encontrada" });

      const cerrada =
        orden.estado === "FINALIZADA" || orden.estado === "ENTREGADA";
      if (cerrada)
        return res.status(409).json({ error: "Orden cerrada: solo lectura" });

      if (!req.file)
        return res
          .status(400)
          .json({ error: "Archivo requerido (field: file)" });

      const { mimetype, originalname, buffer, size } = req.file;
      const ext = safeExt(mimetype);
      if (!ext)
        return res.status(415).json({ error: "Tipo de archivo no soportado" });

      const dir = path.join(
        process.cwd(),
        "uploads",
        "ordenes",
        String(ordenId)
      );
      ensureDir(dir);

      const now = Date.now();
      const baseName = `${now}_${Math.random().toString(16).slice(2)}`;

      let tipo = "FOTO";
      let url = "";
      let thumbnail = null;

      const isImage = mimetype.startsWith("image/");
      const isVideo = mimetype.startsWith("video/");

      if (isVideo && size > 12 * 1024 * 1024) {
        return res
          .status(413)
          .json({ error: "Video demasiado pesado (máx 12MB)" });
      }

      if (isImage) {
        tipo = "FOTO";
        const outFile = `${baseName}.${ext}`;
        fs.writeFileSync(path.join(dir, outFile), buffer);
        url = `/uploads/ordenes/${ordenId}/${outFile}`;
      } else if (isVideo) {
        tipo = "VIDEO";
        const outFile = `${baseName}.${ext}`;
        fs.writeFileSync(path.join(dir, outFile), buffer);
        url = `/uploads/ordenes/${ordenId}/${outFile}`;
        thumbnail = null;
      } else {
        return res.status(415).json({ error: "Archivo no soportado" });
      }

      const evidencia = await prisma.ordenEvidencia.create({
        data: { ordenId, tipo, url, thumbnail },
      });

      await logOrdenEvento({
        ordenId,
        tipo: "EVIDENCIA_AGREGADA",
        detalle: `${
          tipo === "FOTO" ? "Foto" : "Video"
        } agregada: ${originalname}`,
        usuarioId: req.usuario?.id,
      });

      res.json(evidencia);
    } catch (e) {
      console.error(e?.message || e);
      res.status(500).json({ error: "Error subiendo evidencia" });
    }
  }
);

app.get(
  "/api/ordenes/:ordenId/evidencias",
  verificarToken,
  async (req, res) => {
    try {
      const ordenId = Number(req.params.ordenId);
      if (Number.isNaN(ordenId))
        return res.status(400).json({ error: "ordenId inválido" });

      const orden = await prisma.ordenServicio.findUnique({
        where: { id: ordenId },
      });
      if (!orden) return res.status(404).json({ error: "Orden no encontrada" });

      const items = await prisma.ordenEvidencia.findMany({
        where: { ordenId },
        orderBy: { createdAt: "desc" },
      });

      res.json(items);
    } catch (e) {
      console.error(e?.message || e);
      res.status(500).json({ error: "Error cargando evidencias" });
    }
  }
);

/* =========================================================
   Debug (solo NO-PROD)
========================================================= */
if (!IS_PROD) {
  app.get("/debug/env", (req, res) => {
    res.json({
      NODE_ENV: process.env.NODE_ENV,
      has_DATABASE_URL: !!process.env.DATABASE_URL,
      has_JWT_SECRET: !!process.env.JWT_SECRET,
    });
  });
}
    
/* =========================================================
   Arranque (Hostinger / Prod Ready)
========================================================= */
const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 API Taller Coagro corriendo en http://0.0.0.0:${PORT}`);
});
