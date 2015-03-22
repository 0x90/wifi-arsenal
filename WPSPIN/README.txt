

                                     WPSPIN para Linux "spanish versión" 

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  

  Versión windows de maripuri en www.lampiweb.com, versión TR (automática) Windows de Betis-Jesus también en www.lampiweb.com
  El algoritmo FTE-XXXX WPS fue descubierto en unas noches largas pasadas en el grupo de trabajo de lampiweb.com. Y gracias a los datos obtenidos 
con la colaboración de los usuarios de este foro
  Aprovecho para agradecer saltamontes1000 para los datos de redes FTE que me hicieron ver la luz 
  Y gladiator1976 por los de vodafone y FTE que nos vinieron de perla para comprobaciones.
  Y por supuesto a tod@s l@s compis.
  El algoritmo para vodafone, beklin, telnat, Zyxel y Tenda es el mismo que encuentro anteriormente ZaoChunsheng publicado en ComputePIN C83A35 para routeur Tendat. 
  Compota lo vi en HG566 vodafoneXXX,
  Maripuri y Zeiffel (cerca ;)) en telnat Wlan_XXX, 
  Dirneet en tendat y Zyxel
  Fue yo quien lo vi en belkin
  Antares_145 de crack-wifi.com escribió le función checksum en bash, generación y comprobación. Sin el estaría aún intentando entenderla... XD
  Saludos a 1camaron1 y gracias por los scripts que ha dejado en lampiweb.com. me inspire de ellos.
  Least but not last,  gracias a r00tnuLL por sus aportes.

¡NUEVO! 
Se han integrado Los PINes genericos del hilo  http://lampiweb.com/foro/index.php/topic,8188.0.html ;)


  En resumen WPSPIN.sh es la versión linux de un conjunto de herramientas sacadas por el grupo de trabajo de www.lampiweb.com. 
  Utiliza varios algoritmos y incorpora el modo essid-desconocido para FTE (activado automáticamente, les propone tres PINes))              
  Su uso y ejecución son sencillos, les bastará con copiar-pegar los datos desde su ventana airopdump-ng, wash, walsh, wireshark etc...
  Obtendréis el PIN por defecto (3 si es un essid FTE cambiado) y podréis directamente probar suerte con wpsreaver.
  Wpsreaver es de código libre publicado por tacnetsol 2011 http://www.tacnetsol.com/  (tener una versión con opción - p funcional)
  Notar que el script les devolverá el PIN obtenido aplicando el algoritmo "zaoChunsheng" para cualquier routeur no soportado o desconocido (se les notificará cuando es así ).

Quizás tenéis suerte...
                  



                   Para ejecutar el script,
                   -----------------------
 


-1> descomprimir el paquete descargado, 
 
-2> abrir un terminal en el mismo directorio 
 
-3> y escribir "bash WPSPIN.sh" en consola + <Enter> 
           
 
-podéis hacer que el script sea ejecutable con "chmod +x WPSPIN.sh"

Mas detalles en los hilos sobre WPSPIN en lampiweb.com, crack-wifi.com y auditroiaswireless.net



               Para el opción "atacar con reaver"
               --------------------------------
 

- Tener su interfaz ya en mode monitor. Si te suena a Chino pasate por lampiweb.com o visita la web de aircrak-ng  
homepage aircrack-ng >  http://www.aircrack-ng.org/  (salutations à Mr.X)

- Tener instalado reaver wps la ultima revisión de la versión 1.4 (mediante svn) o la versión 1.3 (pasate por lampiweb si te suena también a Chino)
homepage wps-reaver >  reaver//code.google.com/p/reaver-wps/



  
   ¡Para compartir y disfrutar! (GNU GENERAL PUBLIC LICENSE)

                 Saludos de kcdtv ;)

             +-----------+
             | CHANGELOG |
             +-----------+       

10 diciembre 2012 16:13 : 
  Soporte a PINes empezando por 0 gracias a los datos comunicados por atim y tresal. Muchas gracias a los dos.  
10 diciembre 2012 21:28 : 
  Nueva mac soportada : 6A:C0:6F (HG566 con essid vodafoneXXXX )
12 diciembre 2012 14:33 : 
  Versión genérica sin bug de salida en consola en backtrack y otras distribuciones. 
14 diciembre 2012 23:23
  Segunda entrega: Añadidos los pines genéricos conocidos
23 enero 2012
 Tercera entrega, se da soporte a  
  - 7 bSSID nuevos vodafoneXXXX (HG566a) > 6A:3D:FF / 6A:A8:E4 / 6A:C0:6F / 6A:D1:67 / 72:A8:E4 / 72:3D:FF / 72:53:D4 
  - 2 bSSID nuevos WLAN_XXXX (PDG-A4001N de adbroadband) > 74:88:8B / A4:52:6F
  - ¡2 nuevos dispositivos afectados!:
      1) SWL (Samsung Wireless Link), eSSID por defecto SEC_ LinkShare_XXXXXX.  2 bssid soportados conocidos > 80:1F:02 / E4:7C:F9
      2) Conceptronic  c300brs4a  (eSSID por defecto C300BRS4A ) bssid conocido > 00:22:F7   
  Añadidas reglas de comprobación de r00tnull (validez bSSID, mejora filtro essid FTE)
  Más información proporcionada en salida 
  Añadidos filtros para bssid con varios essid por defecto  posibles
  Una sola versión par esta entrega (valida para todas las distribuciones) en lugar de dos                                            
  Re-escritura del código para optimizarlo; ver las anotaciones del código para detalles.
31 enero 2013
 Areglado bug con essid FTE
 Reglas de comprobación nuevas para essid FTE-XXXX (se verifica que el bssid esta en la base de datos, se verifica la conformidad
de la differencia bssid - essid ) 
 - 1 nuevo dispositivo soportado  Zyxel,P-870HNU-51B, WLAN_XXXX > FC:F5:28 


¡Visita las mejores webs del mundo mundial para más detalles!>

www.lampiweb.com
   
www.crack-wifi.com

www.auditoriaswireless.es

www.bentosouto.blogaliza.org

www.wirelesswindows.ucoz.es

www.la-vache-libre.com

www.backtrack.fr

www.inforprograma.net

