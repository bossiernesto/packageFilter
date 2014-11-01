package ar.edu.utn.tadp.aplicacionpartcial;

import org.junit.Assert._
import org.junit.Test

case class Email(
  sujeto: String,
  cuerpo: String,
  destinatario: String,
  receptor: String) {}

object EmailFilter {
  type FiltroEmail = Email => Boolean

  type TuplaComp = (Int, Int) => Boolean
  type TuplaCompCurr = Int => Int => Boolean

  def restriccionTamanio(pred: TuplaComp)( n: Int)( email: Email) = pred(email.cuerpo.size, n)

  val greater_than: TuplaComp = _ > _ //> greater_than  : AplicacionParcial.TuplaComp = <function2>
  val geater_equal_curr: TuplaCompCurr = greater_than.curried
  
  val greater_equal: TuplaComp = _ >= _ //> greater_equal  : AplicacionParcial.TuplaComp = <function2>
  val greater_equal_curr: TuplaCompCurr = greater_equal.curried
  
  val less_than: TuplaComp = _ < _ //> less_than  : AplicacionParcial.TuplaComp = <function2>
  val less_than_curr: TuplaCompCurr = less_than.curried
  
  val less_equal: TuplaComp = _ <= _ //> less_equal  : AplicacionParcial.TuplaComp = <function2>
  val less_equal_curr: TuplaCompCurr = less_equal.curried
  
  val equal: TuplaComp = _ == _ //> equal  : AplicacionParcial.TuplaComp = <function2>
  val equalCurr: TuplaCompCurr =  equal.curried
  
  val tamanioMaximo: (Int, Email) => Boolean = restriccionTamanio(less_equal)( _: Int)( _: Email)
  val restriccionTamanioFuncion: TuplaComp => Int => Email => Boolean = restriccionTamanio _
  
  val menorigual4: Email => Boolean = restriccionTamanioFuncion(less_equal)(4)
}

case class Usuario(name: String)
trait IncomingEmails {
  def getMails(usuario: Usuario, unread: Boolean): Seq[Email]
}

trait EmailFilters {
  def getEmailFilter(usuario: Usuario): EmailFilter.FiltroEmail
}

//Esto es un mixin... 
trait BandejadeEntrada {
  def getNewMails(emailRepo: IncomingEmails)(filtros: EmailFilters)(user: Usuario) =
    emailRepo.getMails(user, true).filter(filtros.getEmailFilter(user))
  val filteredMails: Usuario => Seq[Email]
}

object SimpleIncomingEmails extends IncomingEmails{
  val e1= Email("Hola", "Esto es un mensaje que se filtrara", "a@a.com", "b@b.com")
  val e2:Email= Email("Hola", "Ok", "a@a.com", "b@b.com")
  def getMails(usuario: Usuario, unread: Boolean): Seq[Email] = e1::e2::Nil
}

object SimpleEmailFilter extends EmailFilters {
  import EmailFilter._
  def getEmailFilter(user: Usuario): FiltroEmail = menorigual4 
}

object PABandejadeEntrada extends BandejadeEntrada {
  val filteredMails: (Usuario) => Seq[Email] =
    getNewMails(SimpleIncomingEmails)(SimpleEmailFilter) _
}

class AplicacionParcialTest {

  @Test
  def `tamanio maximo del email es verdadero` = {
    val email = Email("Hola", "Esto es un mensaje", "a@a.com", "b@b.com")
    assertTrue(EmailFilter.tamanioMaximo(30, email))
  }
  
  @Test
  def `4 es menor que 6....`={
    assertTrue(EmailFilter.less_than(4,6))
  }
  
  @Test 
  def `4 es menor que 6.... con currificacion...`={
    assertTrue(EmailFilter.less_than_curr(4)(6))
  }
  
  @Test
  def `tamanio no es menor a 4` ={
    val email2 = Email("Bleh", "Esto es un mensaje mucho mas largo que 4", "", "")
    assertFalse(EmailFilter.menorigual4(email2))
  }
  
  @Test
  def `filtrar mails` = {
    assertEquals(PABandejadeEntrada.filteredMails(Usuario("a@a.com")),SimpleIncomingEmails.e2::Nil)
  }

}
