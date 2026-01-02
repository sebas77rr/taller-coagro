import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

dotenv.config();

if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL no está definida");
  process.exit(1); // corta el server si falta
}    

// Prisma Client (MySQL)
const prisma = new PrismaClient();

// Intento de conexión seguro (no tumba la app)
prisma.$connect()
  .then(() => console.log("✅ DB connected"))
  .catch((e) => console.error("❌ DB connect failed:", e?.message || e));

const app = express();

app.use(cors());
app.use(express.json());   
/* =========================================================
   Helpers: Eventos (auditoría)
========================================================= */

async function logOrdenEvento({ ordenId, tipo, detalle, usuarioId }) {
  try {
    await prisma.ordenEvento.create({
      data: {
        ordenId,
        tipo,
        detalle: detalle || null,
        usuarioId: usuarioId ?? null,
      },
    });
  } catch (e) {
    console.error("No se pudo registrar evento:", e);
  }
}

/* =========================================================
   Middlewares: Auth + Roles
========================================================= */

const verificarToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token inválido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded; // {id, rol, sedeId}
    next();
  } catch (error) {
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
   Rutas: Public
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({ ok: true, message: "API Taller Coagro OK" });
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email y password son obligatorios" });
    }

    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // ✅ Evita 500 por password null/undefined
    if (!usuario.password) {
      return res.status(500).json({
        error: "Usuario sin password en BD (null). Revisa el seed/import.",
      });
    }

    // ✅ Evita 500 por password plano (no hasheado)
    if (!usuario.password.startsWith("$2")) {
      return res.status(500).json({
        error:
          "Password en BD no está hasheado. Debe iniciar con $2 (bcrypt). Revisa import/seed.",
      });
    }

    const passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ error: "JWT_SECRET no configurado" });
    }

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
    console.error("Error login:", error);
    return res.status(500).json({
      error: "Error en login",
      detail: error?.message || String(error),
    });
  }
});

/* =========================================================
   Rutas: Sedes (protegido)
========================================================= */

app.get("/api/sedes", verificarToken, async (req, res) => {
  try {
    const sedes = await prisma.sede.findMany({
      where: { activo: true },
      orderBy: { id: "asc" },
    });
    res.json(sedes);
  } catch (error) {
    console.error("Error listando sedes:", error);
    res.status(500).json({ error: "Error listando sedes" });
  }
});

/* =========================================================
   Rutas: Clientes
========================================================= */

// Listar + search
app.get("/api/clientes", verificarToken, async (req, res) => {
  try {
    const search = (req.query.search || "").toString().trim();

    const where = search
      ? {
          OR: [
            { nombre: { contains: search, mode: "insensitive" } },
            { telefono: { contains: search, mode: "insensitive" } },
            { documento: { contains: search, mode: "insensitive" } },
            { correo: { contains: search, mode: "insensitive" } },
            { empresa: { contains: search, mode: "insensitive" } },
          ],
        }
      : undefined;

    const clientes = await prisma.cliente.findMany({
      where,
      orderBy: { nombre: "asc" },
      take: search ? 20 : 200,
    });

    res.json(clientes);
  } catch (error) {
    console.error("Error listando clientes:", error);
    res.status(500).json({ error: "Error listando clientes" });
  }
});

// Crear cliente (ADMIN / JEFE_TALLER)
app.post(
  "/api/clientes",
  verificarToken,
  soloAdminOJefeTaller,
  async (req, res) => {
    try {
      const { nombre, documento, telefono, correo, empresa } = req.body;

      if (!nombre || String(nombre).trim().length < 3) {
        return res.status(400).json({ error: "nombre es obligatorio (mín 3)" });
      }

      // Control duplicados: documento/telefono/correo
      const or = [];
      if (documento) or.push({ documento: String(documento).trim() });
      if (telefono) or.push({ telefono: String(telefono).trim() });
      if (correo) or.push({ correo: String(correo).trim() });

      if (or.length > 0) {
        const existe = await prisma.cliente.findFirst({ where: { OR: or } });
        if (existe) {
          return res
            .status(409)
            .json({ error: "Cliente ya existe", cliente: existe });
        }
      }

      const nuevo = await prisma.cliente.create({
        data: {
          nombre: String(nombre).trim(),
          documento: documento ? String(documento).trim() : null,
          telefono: telefono ? String(telefono).trim() : null,
          correo: correo ? String(correo).trim() : null,
          empresa: empresa ? String(empresa).trim() : null,
        },
      });

      res.status(201).json(nuevo);
    } catch (error) {
      console.error("Error creando cliente:", error);
      res.status(500).json({ error: "Error creando cliente" });
    }
  }
);

/* =========================================================
   Rutas: Equipos
========================================================= */

// Listar equipos
app.get("/api/equipos", verificarToken, async (req, res) => {
  try {
    const equipos = await prisma.equipo.findMany({
      include: { cliente: true },
      orderBy: { id: "asc" },
    });
    res.json(equipos);
  } catch (error) {
    console.error("Error listando equipos:", error);
    res.status(500).json({ error: "Error listando equipos" });
  }
});

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
      console.error("Error creando equipo:", {
        message: error.message,
        code: error.code,
        meta: error.meta,
      });
      res.status(500).json({ error: "Error creando equipo" });
    }
  }
);

/* =========================================================
   Rutas: Órdenes
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
    console.error("Error creando orden de servicio:", {
      message: error.message,
      code: error.code,
      meta: error.meta,
    });
    res.status(500).json({ error: "Error creando orden de servicio" });
  }
});

// Listar órdenes (filtros opcionales)
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
    console.error("Error listando órdenes:", error);
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
    console.error("Error obteniendo orden:", error);
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
    console.error("Error actualizando estado de orden:", error);
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
      console.error("Error asignando técnico:", error);
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
    console.error("Error listando técnicos:", error);
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
      return res.status(400).json({
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
    console.error("Error agregando mano de obra:", error);
    res.status(500).json({ error: "Error agregando mano de obra" });
  }
});

async function assertOrdenEditable(ordenId) {
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
    console.error("Error listando mano de obra:", error);
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
    console.error("Error listando repuestos:", error);
    res.status(500).json({ error: "Error listando repuestos" });
  }
});

// Crear repuesto (ADMIN/JEFE/TECNICO) + control duplicado por código
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
        return res.status(409).json({
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
      console.error("Error creando repuesto:", error);
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
    console.error("Error agregando repuesto a orden:", error);
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
    console.error("Error listando repuestos:", error);
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
    console.error("Error listando eventos:", error);
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
      return res.status(400).json({
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
      data: {
        nombre,
        email,
        password: hash,
        rol,
        sedeId: sedeIdNum,
      },
      select: {
        id: true,
        nombre: true,
        email: true,
        rol: true,
        sedeId: true,
      },
    });

    res.status(201).json(nuevo);
  } catch (error) {
    console.error("Error creando usuario:", error);
    res.status(500).json({ error: "Error creando usuario" });
  }
});

app.get("/api/usuarios", verificarToken, soloAdmin, async (req, res) => {
  try {
    const usuarios = await prisma.usuario.findMany({
      orderBy: { id: "asc" },
      select: {
        id: true,
        nombre: true,
        email: true,
        rol: true,
        sedeId: true,
      },
    });

    res.json(usuarios);
  } catch (error) {
    console.error("Error listando usuarios:", error);
    res.status(500).json({ error: "Error listando usuarios" });
  }
});

app.patch(
  "/api/ordenes/:ordenId/mano-obra/:itemId",
  verificarToken,
  async (req, res) => {
    try {
      const ordenId = Number(req.params.ordenId);
      const itemId = Number(req.params.itemId);
      const { descripcion, horas } = req.body;

      if (Number.isNaN(ordenId) || Number.isNaN(itemId)) {
        return res.status(400).json({ error: "IDs inválidos" });
      }

      const chk = await assertOrdenEditable(ordenId);
      if (!chk.ok) return res.status(chk.status).json({ error: chk.error });

      const item = await prisma.ordenManoObra.findUnique({
        where: { id: itemId },
      });
      if (!item || item.ordenId !== ordenId) {
        return res.status(404).json({ error: "Mano de obra no encontrada" });
      }

      const horasNum = horas == null ? null : Number(horas);
      if (horasNum !== null && (Number.isNaN(horasNum) || horasNum <= 0)) {
        return res.status(400).json({ error: "Horas inválidas" });
      }

      const upd = await prisma.ordenManoObra.update({
        where: { id: itemId },
        data: {
          descripcionTrabajo:
            descripcion != null
              ? String(descripcion).trim()
              : item.descripcionTrabajo,
          horas: horasNum != null ? horasNum : item.horas,
        },
      });

      await logOrdenEvento({
        ordenId,
        tipo: "MANO_OBRA_EDITADA",
        detalle: `Editó mano de obra #${itemId}: "${item.descripcionTrabajo}" -> "${upd.descripcionTrabajo}", horas ${item.horas} -> ${upd.horas}`,
        usuarioId: req.usuario?.id,
      });

      res.json(upd);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error editando mano de obra" });
    }
  }
);

app.delete(
  "/api/ordenes/:ordenId/mano-obra/:itemId",
  verificarToken,
  async (req, res) => {
    try {
      const ordenId = Number(req.params.ordenId);
      const itemId = Number(req.params.itemId);

      if (Number.isNaN(ordenId) || Number.isNaN(itemId)) {
        return res.status(400).json({ error: "IDs inválidos" });
      }

      const chk = await assertOrdenEditable(ordenId);
      if (!chk.ok) return res.status(chk.status).json({ error: chk.error });

      const item = await prisma.ordenManoObra.findUnique({
        where: { id: itemId },
      });
      if (!item || item.ordenId !== ordenId) {
        return res.status(404).json({ error: "Mano de obra no encontrada" });
      }

      await prisma.ordenManoObra.delete({ where: { id: itemId } });

      await logOrdenEvento({
        ordenId,
        tipo: "MANO_OBRA_ELIMINADA",
        detalle: `Eliminó mano de obra #${itemId}: "${item.descripcionTrabajo}" (${item.horas}h)`,
        usuarioId: req.usuario?.id,
      });

      res.json({ ok: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error eliminando mano de obra" });
    }
  }
);

app.patch(
  "/api/ordenes/:ordenId/repuestos/:itemId",
  verificarToken,
  async (req, res) => {
    try {
      const ordenId = Number(req.params.ordenId);
      const itemId = Number(req.params.itemId);
      const { cantidad, esGarantia } = req.body;

      if (Number.isNaN(ordenId) || Number.isNaN(itemId)) {
        return res.status(400).json({ error: "IDs inválidos" });
      }

      const chk = await assertOrdenEditable(ordenId);
      if (!chk.ok) return res.status(chk.status).json({ error: chk.error });

      const item = await prisma.ordenRepuesto.findUnique({
        where: { id: itemId },
        include: { repuesto: true },
      });

      if (!item || item.ordenId !== ordenId) {
        return res
          .status(404)
          .json({ error: "Repuesto en orden no encontrado" });
      }

      const cantidadNum = cantidad == null ? null : Number(cantidad);
      if (
        cantidadNum !== null &&
        (Number.isNaN(cantidadNum) || cantidadNum <= 0)
      ) {
        return res.status(400).json({ error: "Cantidad inválida" });
      }

      const garantia =
        esGarantia == null ? item.esGarantia : Boolean(esGarantia);

      // V1: costos quedan en 0 o se mantienen; si quieres, recalculas igual sin mostrar (ya lo tienes montado)
      const costoUnitario = garantia ? 0 : item.repuesto?.costo || 0;
      const cantidadFinal = cantidadNum != null ? cantidadNum : item.cantidad;
      const subtotal = costoUnitario * cantidadFinal;

      const upd = await prisma.ordenRepuesto.update({
        where: { id: itemId },
        data: {
          cantidad: cantidadFinal,
          esGarantia: garantia,
          costoUnitario,
          subtotal,
        },
        include: { repuesto: true },
      });

      await logOrdenEvento({
        ordenId,
        tipo: "REPUESTO_EDITADO",
        detalle: `Editó repuesto #${itemId}: "${item.repuesto?.codigo}" cant ${item.cantidad} -> ${upd.cantidad}, garantía ${item.esGarantia} -> ${upd.esGarantia}`,
        usuarioId: req.usuario?.id,
      });
   
      res.json(upd);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error editando repuesto" });
    }
  }
);   

app.delete(
  "/api/ordenes/:ordenId/repuestos/:itemId",     
  verificarToken,
  async (req, res) => {
    try {
      const ordenId = Number(req.params.ordenId);
      const itemId = Number(req.params.itemId);  

      if (Number.isNaN(ordenId) || Number.isNaN(itemId)) {
        return res.status(400).json({ error: "IDs inválidos" });
      }

      const chk = await assertOrdenEditable(ordenId);
      if (!chk.ok) return res.status(chk.status).json({ error: chk.error });

      const item = await prisma.ordenRepuesto.findUnique({
        where: { id: itemId },
        include: { repuesto: true },
      });
    
      if (!item || item.ordenId !== ordenId) {
        return res
          .status(404)
          .json({ error: "Repuesto en orden no encontrado" });
      }   

      await prisma.ordenRepuesto.delete({ where: { id: itemId } });

      await logOrdenEvento({   
        ordenId,    
        tipo: "REPUESTO_ELIMINADO",
        detalle: `Eliminó repuesto #${itemId}: "${item.repuesto?.codigo} · ${item.repuesto?.descripcion}" (cant ${item.cantidad})`,
        usuarioId: req.usuario?.id,
      });

      res.json({ ok: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error eliminando repuesto" }); 
    }
  }
);      


app.get("/debug/env", (req, res) => {
  res.json({
    hasJwt: !!process.env.JWT_SECRET,
    hasDb: !!process.env.DATABASE_URL,
    nodeEnv: process.env.NODE_ENV,
  });
});      

app.get("/debug/login-check", async (req, res) => {
  const email = "admin@coagro.com.co";
  const plain = "Admin2025*"; // la que estás usando

  const usuario = await prisma.usuario.findUnique({ where: { email } });

  const bcryptOk = await bcrypt.compare(plain, usuario.password);

  res.json({
    found: !!usuario,
    bcryptOk,
    userId: usuario?.id,
    rol: usuario?.rol,
    sedeId: usuario?.sedeId,
    hasJwt: !!process.env.JWT_SECRET,
  });
});

app.get("/debug/db", async (req, res) => {
  try {
    await prisma.$connect();
    const count = await prisma.usuario.count();
    res.json({ ok: true, message: "DB OK", usuarios: count });
  } catch (e) {
    res.status(500).json({
      ok: false,
      message: "DB FAIL",
      error: e?.message || String(e),
    });
  }
});      

app.get("/debug/user", async (req, res) => {
  try {
    const email = String(req.query.email || "");
    const usuario = await prisma.usuario.findUnique({ where: { email } });
    res.json({ ok: true, usuario: usuario ? { id: usuario.id, email: usuario.email } : null });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});       


/* =========================================================
   Arranque
========================================================= */

const PORT = process.env.PORT || 4000;

// Healthcheck principal
app.get("/", (req, res) => {
  res.json({ ok: true, message: "API Taller Coagro online" });
});

// Verificación de archivo activo
app.get("/whoami", (req, res) => {
  res.send("SERVER.JS ACTIVO ✅");
});

app.listen(PORT, () => {
  console.log(`🚀 API Taller Coagro corriendo en puerto ${PORT}`);
}); 