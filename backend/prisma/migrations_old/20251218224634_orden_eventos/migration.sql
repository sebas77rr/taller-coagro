-- CreateTable
CREATE TABLE "OrdenEvento" (
    "id" SERIAL NOT NULL,
    "ordenId" INTEGER NOT NULL,
    "tipo" TEXT NOT NULL,
    "detalle" TEXT,
    "usuarioId" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrdenEvento_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "OrdenEvento_ordenId_idx" ON "OrdenEvento"("ordenId");

-- CreateIndex
CREATE INDEX "OrdenEvento_createdAt_idx" ON "OrdenEvento"("createdAt");

-- AddForeignKey
ALTER TABLE "OrdenEvento" ADD CONSTRAINT "OrdenEvento_ordenId_fkey" FOREIGN KEY ("ordenId") REFERENCES "OrdenServicio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
