package ar.edu.utn.tadp.aplicacionpartcial
import org.junit.Assert._
import org.junit.Test

//Objetos básicos
object IPTypes {
  type IPAddrTuple = (Int, Int, Int, Int)
  type CRC32 = String

  implicit class IPAddrTupleComparable[T1, T2, T3, T4](t: (T1, T2, T3, T4)) {
    type R = (T1, T2, T3, T4)
    def equal_than(other: R)(implicit ord: Ordering[R]): Boolean = ord.equiv(t, other)
  }

  //Creo una type class para comparacion y extraccion de un IPAddress
  trait ipaddr[T] {
    def cmp_addr(x: T, y: T): Boolean
    def get_1st_part(x: T): Int
    def get_2nd_part(x: T): Int
    def get_3rd_part(x: T): Int
    def get_4rd_part(x: T): Int
    def get_ip(x: T): IPAddrTuple
  }
  object ipaddr {
    implicit object ippaddrTuple extends ipaddr[IPAddrTuple] {
      def cmp_addr(x: IPAddrTuple, y: IPAddrTuple): Boolean = x.equal_than(y)
      def get_1st_part(x: IPAddrTuple): Int = x._1
      def get_2nd_part(x: IPAddrTuple): Int = x._2
      def get_3rd_part(x: IPAddrTuple): Int = x._3
      def get_4rd_part(x: IPAddrTuple): Int = x._4
      def get_ip(x: IPAddrTuple): IPAddrTuple = x
    }
    implicit object ippaddrString extends ipaddr[String] {
      def separate(x: String): (Int, Int, Int, Int) = x.split("\\.") match {
        case Array(s1, s2, s3, s4) => (s1.toInt, s2.toInt, s3.toInt, s4.toInt)
      }
      def cmp_addr(x: String, y: String): Boolean = x == y
      def get_1st_part(x: String): Int = separate(x)._1
      def get_2nd_part(x: String): Int = separate(x)._2
      def get_3rd_part(x: String): Int = separate(x)._3
      def get_4rd_part(x: String): Int = separate(x)._4
      def get_ip(x: String): IPAddrTuple = separate(x)
    }
  }

}

case class IPPacket[+G](
  version: Int,
  IHL: Int,
  total_length: Int,
  id: Int,
  ttl: Int,
  protocol: String,
  source_ip: G,
  destination_ip: G,
  checksum: IPTypes.CRC32,
  data: String) {

}

object deepPacketInspection {
  import IPTypes._

  type DPIFilter[T] = IPPacket[T] => Boolean

  /*Tuple Comparator structure*/
  type TupleComp = (Int, Int) => Boolean
  type TupleData = (String, String) => Boolean
  type TupleDataCurr = String => String => Boolean
  type TupleCompCurr = Int => Int => Boolean

  type TriTuple = (Int, Int, Int) => Boolean

  /*comparators*/
  val greater_than: TupleComp = _ > _
  val geater_equal_curr: TupleCompCurr = greater_than.curried

  val greater_equal: TupleComp = _ >= _
  val greater_equal_curr: TupleCompCurr = greater_equal.curried

  val less_than: TupleComp = _ < _
  val less_than_curr: TupleCompCurr = less_than.curried

  val less_equal: TupleComp = _ <= _
  val less_equal_curr: TupleCompCurr = less_equal.curried

  val equal: TupleComp = _ == _
  val equalCurr: TupleCompCurr = equal.curried

  val contains: TupleData = _ contains _
  val contains_curr: TupleDataCurr = contains.curried

  val validIPRange = (x: Int, from: Int, to: Int) => from <= x && x <= to
  /*Contraints*/

  //(implicit ip_addr: ipaddr[T])
  def sourceIPConstraint[T: ipaddr](tupl: TriTuple)(from: Int)(to: Int)(packet: IPPacket[T]): Boolean = {
    val ip_addr = implicitly[ipaddr[T]]
    val value = ip_addr.get_1st_part(packet.source_ip)
    tupl(value, from, to)
  }

  def totalSizeConstraint[T](tupl: TupleComp)(n: Int)(packet: IPPacket[T]) = tupl(packet.total_length, n)
  def versionConstraint[T](tupl: TupleComp)(v: Int)(packet: IPPacket[T]) = tupl(packet.version, v)
  def ttlConstraint[T](tupl: TupleComp)(ttl: Int)(packet: IPPacket[T]) = tupl(packet.ttl.toInt, ttl)
  def dataConstraint[T](tupl: TupleData)(pattern: String)(packet: IPPacket[T]) = tupl(packet.data, pattern)

  /*Currying it*/
  def constrainFunction[T]: TupleComp => Int => IPPacket[T] => Boolean = totalSizeConstraint _
  def constrainFunctionVersion[T]: TupleComp => Int => IPPacket[T] => Boolean = versionConstraint _
  def constrainFunctionTTL[T]: TupleComp => Int => IPPacket[T] => Boolean = ttlConstraint _
  def constraintFunctionData[T]: TupleData => String => IPPacket[T] => Boolean = dataConstraint _
  def constraintFunctionSourceIP[T: ipaddr]: TriTuple => Int => Int => IPPacket[T] => Boolean = {
    sourceIPConstraint _
  }
  /*Filters*/
  val max_packet_size = 65535
  val supported_version = 4
  val shellcode_example = "\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80"

  def packetSizeMax[T]: IPPacket[T] => Boolean = constrainFunction(less_equal)(max_packet_size)
  def versionSupported[T]: IPPacket[T] => Boolean = constrainFunctionVersion(equal)(supported_version)
  def ttlGreaterThan0[T]: IPPacket[T] => Boolean = constrainFunctionTTL(greater_than)(0)
  def dataWithShellcode[T]: IPPacket[T] => Boolean = constraintFunctionData(contains)(shellcode_example)
  def validSourceIPAddress[T: ipaddr]: IPPacket[T] => Boolean = {
    val ip_addr = implicitly[ipaddr[T]]
    constraintFunctionSourceIP(ip_addr)(validIPRange)(0)(255)
  }
}

case class Network(network_name: String)
trait DPIFilters {
  def filterPackets[T]: deepPacketInspection.DPIFilter[T]
}

//Esto es un mixin... 
trait MailBoxNetwork {
  def getfilteredPackets[T](packages: Seq[IPPacket[T]], filters: DPIFilters, network_name: Network): Seq[IPPacket[T]] = {
    packages.filter(filters.filterPackets)
  }
  def filteredPackages[T](packages: Seq[IPPacket[T]]): Seq[IPPacket[T]]
}

object SimpleDPIFilters extends DPIFilters {
  import deepPacketInspection._
  def filterPackets[T]: DPIFilter[T] = {
    dataWithShellcode
  }
}

object SimpleMailBoxNetwork extends MailBoxNetwork {
  def filteredPackages[T](packages: Seq[IPPacket[T]]): Seq[IPPacket[T]] = {
    getfilteredPackets(packages, SimpleDPIFilters, Network(""))
  }
}

class DPITest {

  /*test IPAddrTuple*/
  @Test
  def `comparar dos direcciones de IP identicas` = {
    import IPTypes.IPAddrTupleComparable
    val dir1: IPTypes.IPAddrTuple = (12, 2, 4, 5)
    val dir2: IPTypes.IPAddrTuple = (12, 2, 4, 5)
    assertTrue(dir1.equal_than(dir2))
  }

  /*test type class IPAddress*/
  @Test
  def `test sobre type class String` = {
    val ips = List("12.34.34.1", "122.53.51.1", "344.12.55.1")
    import IPTypes._
    def lessThan255[T](xs: List[T])(implicit ev: ipaddr[T]): List[T] = {
      xs.filter(p => ev.get_1st_part(p) < 255)
    }

    assertEquals(lessThan255(ips), List("12.34.34.1", "122.53.51.1"))

  }

  @Test
  def `test sobre type class Tuple` = {
    val ips = List((12, 34, 34, 1), (122, 53, 51, 1), (344, 12, 55, 1))
    import IPTypes._
    def lessThan255[T](xs: List[T])(implicit ev: ipaddr[T]): List[T] = {
      xs.filter(p => ev.get_1st_part(p) < 255)
    }

    assertEquals(lessThan255(ips), List((12, 34, 34, 1), (122, 53, 51, 1)))

  }

  @Test
  def `test sobre type class String comparacion` = {
    val ip1 = "12.34.34.1"
    val ip2 = "122.53.51.1"
    import IPTypes._

    def comp_ips[T](ip1: T, ip2: T)(implicit ip: ipaddr[T]): Boolean = {
      ip.cmp_addr(ip1, ip2)
    }

    assertFalse(comp_ips(ip1, ip2))
  }

  @Test
  def `test sobre type class Tuple comparacion` = {
    val ip1 = (200, 61, 30, 18)
    val ip2 = ip1
    import IPTypes._

    def comp_ips[T](ip1: T, ip2: T)(implicit ip: ipaddr[T]): Boolean = {
      ip.cmp_addr(ip1, ip2)
    }

    assertTrue(comp_ips(ip1, ip2))
  }

  /*test comparators*/
  @Test
  def `4 es menor que 6....` = {
    assertTrue(deepPacketInspection.less_than(4, 6))
  }

  @Test
  def `4 es menor que 6.... con currificacion...` = {
    assertTrue(deepPacketInspection.less_than_curr(4)(6))
  }

  @Test
  def `test comparator contains` = {
    assertTrue(deepPacketInspection.contains("The grey fox", "fox"))
  }

  @Test
  def `test comparator not contains` = {
    assertFalse(deepPacketInspection.contains_curr("The grey fox")("something"))
  }

  /*Test package filters*/
  @Test
  def `test filtering package` = {
    import deepPacketInspection._
    val package1 = IPPacket(4, 5, 54, 42350, 21, "ICMP", "192.53.1.58", "200.12.5.1", "3229570480", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\x01\\x79\\x06\\x08\\x00\\x45\\x20\\x00\\x3C\\x16\\xDB\\x00\\x00\\x3F\\x06\\xCC\\x8A\\xD5\\xE9\\xAB\\x0A\\x5E\\xB6\\xB8\\x8C\\x05\\x57\\x90\\x1F\\x90\\x30\\x93\\x71\\x75\\xF5\\xDB\\xBA\\xA0\\x12\\x16\\x28\\xEF\\xE6")

    assertFalse(dataWithShellcode(package1))
    assertTrue(versionSupported(package1))
    assertTrue(packetSizeMax(package1))
  }

  @Test
  def `test filter shellcoded package` = {
    import deepPacketInspection._
    val package_shellcoded = IPPacket(4, 5, 535, 34447, 56, "SSH", "201.34.64.9", "200.12.5.1", "3193793826", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80\\xAB\\x0A\\x5E")

    assertTrue(dataWithShellcode(package_shellcoded))
    assertTrue(ttlGreaterThan0(package_shellcoded))
  }

  @Test
  def `test validIPRange` = {
    import deepPacketInspection._

    assertTrue(validIPRange(234, 0, 255))
    assertFalse(validIPRange(274, 0, 255))
  }

  @Test
  def `test filter package by IP String` = {
    import deepPacketInspection._
    import IPTypes._
    val correct_package = IPPacket(4, 5, 535, 34447, 56, "SSH", "201.34.64.9", "200.12.5.1", "3193793826", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80\\xAB\\x0A\\x5E")
    val incorrect_package = IPPacket(4, 5, 535, 34447, 56, "SSH", "503.34.64.9", "200.12.5.1", "3193793826", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80\\xAB\\x0A\\x5E")

    implicit val ip_addr = ipaddr.ippaddrString

    assertTrue(validSourceIPAddress(ip_addr)(correct_package))
    assertFalse(validSourceIPAddress(ip_addr)(incorrect_package))
  }

  @Test
  def `test filter package by IP tuple` = {
    import deepPacketInspection._
    import IPTypes._
    val correct_package = IPPacket(4, 5, 535, 34447, 56, "SSH", (201, 34, 64, 9), (200, 12, 5, 1), "3193793826", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80\\xAB\\x0A\\x5E")
    val incorrect_package = IPPacket(4, 5, 535, 34447, 56, "SSH", (503, 34, 64, 9), (200, 12, 5, 1), "3193793826", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80\\xAB\\x0A\\x5E")

    implicit val ip_addr = ipaddr.ippaddrTuple

    assertTrue(validSourceIPAddress(ip_addr)(correct_package))
    assertFalse(validSourceIPAddress(ip_addr)(incorrect_package))
  }

  /*TODO: test integral*/
  @Test
  def `test integral` = {
    val pack1 = IPPacket(4, 5, 535, 34447, 56, "SSH", "201.34.64.9", "200.12.5.1", "3193793826", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\\\x31\\xc0\\x66\\xba\\x0e\\x27\\x66\\x81\\xea\\x06\\x27\\xb0\\x37\\xcd\\x80\\xAB\\x0A\\x5E")
    val pack2 = IPPacket(4, 5, 54, 42350, 21, "ICMP", "192.53.1.58", "200.12.5.1", "3229570480", "00\\x24\\x8C\\x01\\x79\\x08\\x00\\x24\\x8C\\x01\\x79\\x06\\x08\\x00\\x45\\x20\\x00\\x3C\\x16\\xDB\\x00\\x00\\x3F\\x06\\xCC\\x8A\\xD5\\xE9\\xAB\\x0A\\x5E\\xB6\\xB8\\x8C\\x05\\x57\\x90\\x1F\\x90\\x30\\x93\\x71\\x75\\xF5\\xDB\\xBA\\xA0\\x12\\x16\\x28\\xEF\\xE6")
    val packages = Seq(pack1, pack2)
    val expected_seq = Seq(pack1)

    assertEquals(expected_seq, SimpleMailBoxNetwork.filteredPackages(packages))

  }

}
