package ar.edu.utn.tadp.aplicacionpartcial

import org.junit.Assert.assertEquals
import org.junit.Test

case class MilliGramos(val peso: Int)
case class Gramos(val peso: Int) {
  def +(g: Gramos) = Gramos(peso + g.peso)
}
case class Kilos(val peso: Int)

case class Elemento(val nombre: String, val cantidad: Gramos)

class UnidadesFactory(valor: Int) {
  def kilos = Kilos(valor)
  def gramos = Gramos(valor)
  def milligramos = MilliGramos(valor)
}

class ImplicitsTest {

  @Test
  def `implicit conversion parameter` = {
    implicit def stringToList(s: String): Array[String] = s.split("").drop(1)

    def hipenize(a: Array[String]) = a.drop(1).foldLeft(a(0))((a, s) => a + "-" + s)
    assertEquals("h-o-l-a", hipenize("hola"))
  }

  @Test
  def `implicit conversion receiver` = {
    implicit def intToRange(i: Int): List[Int] = (0 until i + 1).toList

    assertEquals(5 + 4 + 3 + 2 + 1 + 0, 5 sum)

  }

  implicit def kilosToGramos(k: Kilos): Gramos = 
    Gramos(k.peso * 1000)
  
  implicit def milligramosToGramos(m: MilliGramos): Gramos = 
    Gramos(m.peso / 1000)

  implicit def intToUnidadesFactory(i: Int): UnidadesFactory = 
    new UnidadesFactory(i)

  def mezclar(elemento: Elemento, otroElemento: Elemento) =
    Elemento(elemento.nombre + otroElemento.nombre, 
        Gramos(elemento.cantidad.peso + 
            otroElemento.cantidad.peso))

  @Test
  def `unidades conversion parameter` = {
    val mercurio = Elemento("Mercurio", Kilos(1))
    val potasio = Elemento("Potasio", MilliGramos(200000))

    val mp = mezclar(mercurio, potasio)
    assertEquals(1200, mp.cantidad.peso)

  }

  @Test
  def `unidades conversion receiver` = {

    val mercurio = Elemento("Mercurio", new Kilos(1))
    val potasio = Elemento("Potasio", 200000 milligramos)

    val mp = mezclar(mercurio, potasio)
    assertEquals(1200, mp.cantidad.peso)

  }


  @Test
  def `sum unidades ` = {
    assertEquals(Gramos(3), Gramos(1) + Gramos(2))
    assertEquals(Gramos(1201), 1.kilos + 200.gramos 
        + 1000.milligramos)
  }

}






