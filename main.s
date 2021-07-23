.data	
    password: .dword 0x6569646e65727041, 0x446f676c416f646e, 0x456f747079724365, 0x4d5241794d53416e
    some1:    .dword 0x5ccc37dea1dac139, 0x35e30b4c16fd0fc8, 0xd1a1109f53e3430 , 0x6c72624c252b0207
    some2:    .dword 0x754758517c43534d, 0x74517f857b7e784d, 0x857a84557f798054, 0x608e8f81897e827d
    status:   .dword 0x6974707972636564, 0x2e2e2e676e
    _stack_ptr: .dword _stack_end   // Get the stack pointer value from memmap definition

.text   // Configuracion del Stack Pointer
        ldr     x1, _stack_ptr  
        mov     sp, x1     
	
        MOV X0, XZR
        MOV X4, XZR
	
main:
        LDR X0, =password	  //X0 = Dirección base del arreglo "password"
        LDR X1, =some1	  	  //X1 = Dirección base del arreglo "Ciphertext"
        LDR X2, =some2	  	  //X2 = Dirección base del arreglo "Cadena auxiliar"
        LDR X5, =status	          //X5 = Dirección base del arreglo "status"

        mov x3, 0x20
        add x11, x2, 0x100

/* La funcion "a" Carga el arreglo some2 (cadena auxiliar) de manera invertida,(de atras para adelante)
en X11 para luego utilizarlo en la funcion "b" y "d" */

        mov x8, x3
a:      sub x8, x8, 0x1   
        add x7, x2, x8           
        ldurb w20, [x7]    
        sturb w20, [x11]
        add x11, x11, 0x1
        cbnz x8, a

/* La funcion "b" verifica que la clave ingresada sea la correcta, y si es asi salta a la funcion d para
descifrar el ciphertext. Si al menos un byte de la key es erroneo saltara a la funcion c para 
cambiar el arreglo status por "failed...". 
Analizando esta funcion y haciendo algunos calculos puede obtenerse la clave. Lo que hace en cada ciclo es
la resta entre cada byte de la cadena auxiliar (some2) ya invertida, con cada byte de la clave ingresada y
queda el resultado en X22. 
Si la clave es correcta, el resultado en cada ciclo sera desde 1f (1er ciclo) hasta 00 (ultimo ciclo); a su
vez estos resultados son los valores que va teniendo X8 en cada ciclo. De modo que luego al hacer la resta
entre X22 y X8 ésta siempre de 0 para evitar el salto a la funcion c (failed). Realizara este metodo hasta
terminar de verificar todos los bytes de la clave ingresada.
La manera de obtener la clave es hacer uno mismo la resta byte a byte entre la cadena auxiliar invertida y
el valor de X8 en cada ciclo. Por ej, en el primer ciclo, X8 = 1f, el primer byte de la cadena auxiliar
invertida es 60, entonces 60-1f= 41. Este resultado es el primer byte de la clave que debemos descifrar */

        mov x8, x3
        mov x7, xzr
        add x15, x2, 0x100
        mov x11, x15
b:      sub x8, x8, 0x1 
        add x10, x0, x7
        add x11, x15, x7
        ldurb w20, [x10]
        ldurb w21, [x11]
        sub x22, x21, x20
        sub x22, x22, x8
        cbnz x22, c
        cbz x8, d
        add x7, x7, 0x1                
        bl b

/*La funcion "c" modifica el arreglo status mostrando "failed..." en lugar de "decrypting..."*/

c:      movk x7, 0x2121, LSL 48
        movk x7, 0x6465, LSL 32
        movk x7, 0x6c69, LSL 16
        movk x7, 0x6146      
        stur x7, [x5]
        stur xzr, [x5,8]
        bl end

/* La funcion "d" descifra el mensaje cifrado en some1. Lo logra haciendo una Xor byte a byte entre los
 arreglos ciphertext y la cadena auxiliar (la cadena auxiliar invertida por la funcion "a") */

d:      eor x7, x7, x7	
        add x15, x2, 0x100
d1:     add x11, x15, x7
        add x12, x1, x7
        ldurb w20, [x11] 
        ldurb w21, [x12]
        eor w20, w20, w21
        sturb w20, [x12] 
        sub x8, x7, 0x1f
        add x7, x7, 0x1
        cbnz x8, d1

end:
        add xzr, xzr, xzr
        B end
