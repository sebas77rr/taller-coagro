import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pkg from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";

dotenv.config();

const { PrismaClient } = pkg;

// mismo pool/adapter que en server.js
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

const crearAdmin = async () => {
  try {
    const passwordPlano = "Admin2025*";
    const hash = await bcrypt.hash(passwordPlano, 10);

    const admin = await prisma.usuario.create({
      data: {
        nombre: "Administrador General",
        email: "admin@coagro.com.co",
        password: hash,
        rol: "ADMIN",
        sedeId: 2, // ajusta al id real de tu Sede Principal
      },
    });

    console.log("✅ Admin creado:", {
      id: admin.id,
      email: admin.email,
      rol: admin.rol,
    });
  } catch (error) {
    console.error("❌ Error creando admin:", {
      message: error.message,
      code: error.code,
      meta: error.meta,
    });
  } finally {
    await prisma.$disconnect();
    process.exit();
  }
};

crearAdmin();