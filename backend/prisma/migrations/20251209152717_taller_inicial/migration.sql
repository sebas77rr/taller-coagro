-- CreateEnum
CREATE TYPE "TipoSede" AS ENUM ('PRINCIPAL', 'PUNTO_VENTA');

-- CreateEnum
CREATE TYPE "RolUsuario" AS ENUM ('ADMIN', 'JEFE_TALLER', 'TECNICO', 'ALMACEN', 'CONSULTA');

-- CreateEnum
CREATE TYPE "TipoIngreso" AS ENUM ('GARANTIA', 'MANTENIMIENTO', 'REPARACION');

-- CreateEnum
CREATE TYPE "EstadoOrden" AS ENUM ('ABIERTA', 'EN_PROCESO', 'ESPERANDO_REPUESTO', 'FINALIZADA', 'ENTREGADA');

-- CreateTable
CREATE TABLE "Sede" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,
    "tipoSede" "TipoSede" NOT NULL,
    "ciudad" TEXT NOT NULL,
    "direccion" TEXT NOT NULL,
    "activo" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "Sede_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Usuario" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "rol" "RolUsuario" NOT NULL,
    "sedeId" INTEGER,

    CONSTRAINT "Usuario_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Cliente" (
    "id" SERIAL NOT NULL,
    "nombre" TEXT NOT NULL,
    "documento" TEXT,
    "telefono" TEXT,
    "correo" TEXT,
    "empresa" TEXT,

    CONSTRAINT "Cliente_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Equipo" (
    "id" SERIAL NOT NULL,
    "clienteId" INTEGER NOT NULL,
    "marca" TEXT NOT NULL,
    "modelo" TEXT NOT NULL,
    "serial" TEXT NOT NULL,
    "descripcion" TEXT,

    CONSTRAINT "Equipo_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrdenServicio" (
    "id" SERIAL NOT NULL,
    "codigo" TEXT NOT NULL,
    "sedeId" INTEGER NOT NULL,
    "clienteId" INTEGER NOT NULL,
    "equipoId" INTEGER NOT NULL,
    "tipoIngreso" "TipoIngreso" NOT NULL,
    "motivoIngreso" TEXT NOT NULL,
    "estado" "EstadoOrden" NOT NULL DEFAULT 'ABIERTA',
    "fechaIngreso" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "fechaSalida" TIMESTAMP(3),
    "tecnicoId" INTEGER,

    CONSTRAINT "OrdenServicio_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrdenManoObra" (
    "id" SERIAL NOT NULL,
    "ordenId" INTEGER NOT NULL,
    "descripcionTrabajo" TEXT NOT NULL,
    "horas" DOUBLE PRECISION NOT NULL,
    "costoHora" DOUBLE PRECISION NOT NULL,
    "subtotal" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "OrdenManoObra_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Repuesto" (
    "id" SERIAL NOT NULL,
    "codigo" TEXT NOT NULL,
    "descripcion" TEXT NOT NULL,
    "costo" DOUBLE PRECISION NOT NULL,
    "stockGlobal" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "Repuesto_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrdenRepuesto" (
    "id" SERIAL NOT NULL,
    "ordenId" INTEGER NOT NULL,
    "repuestoId" INTEGER NOT NULL,
    "cantidad" INTEGER NOT NULL,
    "costoUnitario" DOUBLE PRECISION NOT NULL,
    "esGarantia" BOOLEAN NOT NULL DEFAULT false,
    "subtotal" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "OrdenRepuesto_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Usuario_email_key" ON "Usuario"("email");

-- CreateIndex
CREATE UNIQUE INDEX "OrdenServicio_codigo_key" ON "OrdenServicio"("codigo");

-- CreateIndex
CREATE UNIQUE INDEX "Repuesto_codigo_key" ON "Repuesto"("codigo");

-- AddForeignKey
ALTER TABLE "Usuario" ADD CONSTRAINT "Usuario_sedeId_fkey" FOREIGN KEY ("sedeId") REFERENCES "Sede"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Equipo" ADD CONSTRAINT "Equipo_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "Cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenServicio" ADD CONSTRAINT "OrdenServicio_sedeId_fkey" FOREIGN KEY ("sedeId") REFERENCES "Sede"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenServicio" ADD CONSTRAINT "OrdenServicio_clienteId_fkey" FOREIGN KEY ("clienteId") REFERENCES "Cliente"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenServicio" ADD CONSTRAINT "OrdenServicio_equipoId_fkey" FOREIGN KEY ("equipoId") REFERENCES "Equipo"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenServicio" ADD CONSTRAINT "OrdenServicio_tecnicoId_fkey" FOREIGN KEY ("tecnicoId") REFERENCES "Usuario"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenManoObra" ADD CONSTRAINT "OrdenManoObra_ordenId_fkey" FOREIGN KEY ("ordenId") REFERENCES "OrdenServicio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenRepuesto" ADD CONSTRAINT "OrdenRepuesto_ordenId_fkey" FOREIGN KEY ("ordenId") REFERENCES "OrdenServicio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrdenRepuesto" ADD CONSTRAINT "OrdenRepuesto_repuestoId_fkey" FOREIGN KEY ("repuestoId") REFERENCES "Repuesto"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
