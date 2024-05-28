import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import filedialog
from tkinter import messagebox

import random


class Enigma:
    def __init__(self):
        self.teclado = list(range(256))
        self.reflector = [202, 236, 220, 86, 15, 222, 152, 129, 73, 190, 231, 44, 232, 55, 63, 188, 181, 53, 29, 188, 168, 22, 1, 0, 186, 124, 245, 139, 100, 185, 79, 187, 248, 241, 38, 199, 215, 42, 45, 244, 231, 229, 152, 202, 50, 72, 52, 41, 203, 116, 67, 61, 52, 103, 131, 6, 206, 161, 0, 3, 86, 243, 115, 13, 205, 140, 174, 19, 232, 29, 96, 120, 79, 245, 6, 131, 60, 55, 191, 115, 163, 240, 160, 84, 214, 128, 145, 44, 84, 118, 191, 163, 213, 181, 154, 19, 186, 234, 182, 247, 91, 7, 167, 34, 46, 167, 18, 122, 23, 51, 16, 74, 233, 244, 199, 249, 87, 241, 227, 200, 168, 185, 145, 50, 48, 96, 233, 49, 67, 135, 172, 118, 154, 136, 144, 18, 192, 54, 5, 173, 21, 184, 1, 92, 247, 58, 60, 100, 82, 116, 200, 38, 224, 157, 173, 224, 193, 81, 215, 122, 82, 220, 157, 14, 243, 182, 214, 144, 134, 227, 149, 165, 150, 102, 134, 156, 54, 149, 184, 248, 252, 136, 192, 128, 5, 65, 8, 14, 34, 72, 172, 13, 21, 190, 7, 165, 161, 129, 103, 73, 139, 249, 222, 8, 53, 160, 193, 212, 240, 234, 74, 156, 49, 61, 216, 216, 3, 48, 58, 205, 92, 87, 42, 102, 209, 206, 22, 236, 194, 88, 140, 51, 120, 209, 229, 63, 81, 174, 41, 124, 15, 187, 46, 65, 23, 135, 150, 45, 252, 203, 88, 194, 212, 213, 91, 16]
        r1 = [107, 84, 42, 89, 171, 181, 169, 31, 245, 172, 122, 98, 2, 77, 205, 217, 254, 27, 216, 78, 174, 60, 19, 163, 63, 69, 44, 143, 74, 8, 14, 102, 18, 52, 220, 137, 151, 131, 193, 105, 182, 117, 114, 90, 7, 192, 136, 50, 16, 223, 53, 25, 241, 9, 247, 243, 91, 111, 202, 112, 178, 96, 21, 73, 214, 141, 119, 81, 3, 104, 164, 30, 100, 176, 134, 39, 59, 157, 240, 110, 17, 251, 213, 106, 159, 215, 252, 68, 49, 155, 160, 175, 75, 165, 231, 126, 225, 83, 224, 34, 95, 236, 61, 92, 66, 67, 167, 184, 238, 200, 198, 85, 173, 207, 65, 15, 23, 94, 87, 5, 55, 72, 221, 62, 48, 109, 103, 218, 244, 138, 6, 125, 170, 1, 158, 120, 208, 219, 199, 153, 168, 32, 227, 248, 166, 124, 12, 20, 237, 250, 101, 191, 29, 195, 28, 99, 10, 82, 115, 64, 235, 93, 35, 149, 0, 97, 186, 150, 144, 255, 228, 123, 88, 233, 209, 140, 162, 70, 24, 132, 4, 232, 203, 37, 188, 185, 38, 108, 161, 41, 26, 43, 230, 234, 36, 33, 40, 226, 80, 113, 222, 139, 57, 47, 133, 142, 190, 156, 189, 239, 147, 180, 128, 145, 54, 56, 152, 197, 201, 118, 148, 206, 127, 210, 194, 253, 246, 79, 204, 46, 58, 129, 177, 154, 179, 249, 13, 135, 71, 116, 121, 76, 130, 45, 211, 212, 86, 242, 183, 146, 51, 187, 11, 22, 229, 196]
        r2 = [52, 224, 23, 55, 230, 204, 61, 135, 250, 116, 95, 13, 18, 104, 58, 7, 168, 181, 24, 170, 158, 66, 21, 60, 108, 2, 45, 80, 3, 140, 165, 130, 167, 238, 159, 153, 68, 150, 47, 227, 126, 12, 212, 149, 247, 252, 102, 62, 84, 118, 220, 186, 218, 151, 79, 11, 175, 82, 43, 144, 180, 215, 221, 88, 117, 169, 128, 26, 78, 206, 171, 92, 67, 69, 91, 233, 129, 107, 32, 48, 59, 121, 83, 145, 132, 229, 207, 27, 236, 225, 30, 152, 178, 97, 74, 248, 133, 41, 240, 114, 242, 71, 77, 53, 72, 208, 216, 125, 182, 50, 194, 123, 42, 249, 127, 202, 36, 190, 22, 111, 103, 1, 211, 160, 56, 9, 70, 163, 246, 241, 156, 184, 164, 86, 231, 235, 73, 16, 185, 201, 147, 14, 251, 142, 81, 29, 188, 0, 49, 34, 44, 99, 38, 199, 40, 131, 137, 54, 106, 209, 17, 155, 146, 112, 254, 196, 57, 110, 85, 239, 93, 139, 197, 33, 109, 214, 172, 161, 136, 115, 148, 65, 245, 100, 189, 96, 35, 192, 226, 203, 119, 87, 223, 162, 205, 176, 90, 191, 228, 15, 19, 179, 37, 200, 157, 120, 195, 234, 51, 124, 105, 5, 89, 166, 113, 46, 210, 122, 134, 39, 232, 31, 101, 237, 183, 10, 76, 25, 98, 64, 8, 255, 174, 173, 143, 193, 28, 253, 63, 94, 177, 243, 244, 141, 75, 6, 222, 219, 4, 217, 198, 20, 138, 213, 154, 187]
        r3 = [147, 226, 69, 171, 229, 146, 215, 117, 246, 8, 183, 227, 202, 170, 225, 237, 239, 51, 245, 90, 228, 217, 23, 123, 135, 43, 22, 81, 231, 224, 241, 108, 236, 207, 83, 49, 148, 167, 75, 185, 255, 253, 31, 188, 196, 244, 93, 86, 250, 232, 95, 37, 119, 219, 65, 159, 216, 114, 42, 152, 63, 44, 133, 166, 87, 14, 164, 113, 214, 158, 142, 105, 38, 53, 143, 76, 50, 160, 82, 233, 35, 195, 138, 178, 101, 59, 141, 115, 169, 168, 92, 213, 5, 45, 127, 190, 174, 191, 60, 32, 248, 6, 103, 180, 99, 151, 198, 125, 107, 187, 91, 139, 206, 80, 192, 25, 116, 157, 11, 77, 110, 161, 247, 40, 136, 55, 98, 12, 144, 13, 73, 218, 54, 172, 64, 85, 79, 21, 154, 52, 212, 102, 78, 4, 210, 252, 130, 122, 0, 204, 10, 162, 137, 106, 182, 72, 27, 205, 238, 74, 39, 181, 94, 203, 235, 140, 112, 230, 28, 153, 7, 84, 124, 149, 104, 96, 155, 24, 48, 251, 15, 179, 243, 175, 29, 222, 177, 33, 134, 220, 129, 184, 156, 97, 30, 121, 109, 1, 242, 20, 176, 67, 163, 221, 240, 194, 88, 211, 66, 186, 18, 201, 19, 71, 68, 2, 41, 47, 199, 208, 120, 209, 234, 254, 197, 61, 145, 189, 70, 16, 118, 128, 3, 150, 223, 57, 46, 58, 36, 34, 56, 111, 62, 9, 89, 200, 193, 131, 100, 126, 17, 132, 173, 249, 26, 165]
        self.rotor1 = list(zip(self.teclado, r1))
        self.rotor2 = list(zip(self.teclado, r2))
        self.rotor3 = list(zip(self.teclado, r3))

    def avance_rotor(self, rotor, paso):
        cuenta = 0
        while cuenta < paso:
            rotor.append(rotor.pop(0))
            cuenta += 1
        return rotor
    
    def conf_rotores(self, clave_inicial):
        while clave_inicial[0] != self.rotor1[0][0]:
            self.rotor1.append(self.rotor1.pop(0))
        while clave_inicial[1] != self.rotor2[0][0]:
            self.rotor2.append(self.rotor2.pop(0))
        while clave_inicial[2] != self.rotor3[0][0]:
            self.rotor3.append(self.rotor3.pop(0))

    def senal(self, rotor, indice, direccion):
        letra_entrada = rotor[indice][direccion]
        indice_salida = 0
        for pares in rotor:
            if pares[abs(direccion-1)] != letra_entrada:
                indice_salida += 1
            else:
                break
        return letra_entrada, indice_salida

    def indice_reflector(self, disco, indice):
        letra_entrada = disco[indice]
        if indice == (len(disco) - 1):
            for i in range(len(disco)):
                if disco[i] == letra_entrada:
                    return letra_entrada, i
        else:
            for j in range(indice + 1, len(disco)):
                if disco[j] == letra_entrada:
                    return letra_entrada, j
                else:
                    for k in range(indice):
                        if disco[k] == letra_entrada:
                            return letra_entrada, k

    def intercambiar_letras(self, lista_letra1, lista_letra2):
        if len(lista_letra1) != len(lista_letra2):
            print("Error: Las listas no tienen el mismo tamaño.")
            return

        for letra1, letra2 in zip(lista_letra1, lista_letra2):
            if letra1 in self.teclado and letra2 in self.teclado:
                indice_letra1 = self.teclado.index(letra1)
                indice_letra2 = self.teclado.index(letra2)
                self.teclado[indice_letra1], self.teclado[indice_letra2] = self.teclado[indice_letra2], self.teclado[indice_letra1]
            else:
                print(f"Error: Uno de los valores {letra1} o {letra2} no está en el teclado.")

    def load_archivo(self, ruta):
        try:
            with open(ruta, 'rb') as archivo:
                datos = archivo.read()
                datos_list = list(datos)
            return datos_list
        except FileNotFoundError:
            print("El archivo no fue encontrado.")
            return None
        except Exception as e:
            print(f"Ocurrió un error al leer el archivo: {e}")
            return None

    def guardar_archivo_cifrado(self, datos_cifrados, ruta_archivo):
        try:
            datos_en_bytes = bytes(datos_cifrados)
            with open(ruta_archivo, 'wb') as archivo:
                archivo.write(datos_en_bytes)
            print("Archivo cifrado guardado correctamente.")
        except IOError as e:
            print(f"Ocurrió un error al guardar el archivo: {e}")

    def enigma(self, mensaje, clave, turnover, lista_letra1, lista_letra2):
        self.conf_rotores(clave)
        self.intercambiar_letras(lista_letra1, lista_letra2)
        mensaje_final_bytes = []
        for i in mensaje:
            self.avance_rotor(self.rotor3, 1)
            if self.rotor3[-1][0] == turnover[2]:
                self.avance_rotor(self.rotor2, 1)
                if self.rotor2[-1][0] == turnover[1]:
                    self.avance_rotor(self.rotor1, 1)

            indice_entrada = self.teclado.index(i)

            primer_paso = self.senal(self.rotor3, indice_entrada, 1)
            segundo_paso = self.senal(self.rotor2, primer_paso[1], 1)
            tercer_paso = self.senal(self.rotor1, segundo_paso[1], 1)
            rebote = self.indice_reflector(self.reflector, tercer_paso[1])
            cuarto_paso = self.senal(self.rotor1, rebote[1], 0)
            quinto_paso = self.senal(self.rotor2, cuarto_paso[1], 0)
            sexto_paso = self.senal(self.rotor3, quinto_paso[1], 0)
            self.intercambiar_letras(lista_letra2, lista_letra1)
            mensaje_final_bytes.append(self.teclado[sexto_paso[1]])

        return mensaje_final_bytes


class EnigmaApp:
    def __init__(self, root, enigma):
        self.root = root
        self.root.title("Enigma Machine")
        self.enigma = enigma

        self.create_widgets()
        self.enigma.lista_letra1 = []
        self.enigma.lista_letra2 = []

    def create_widgets(self):
        self.message_entry = ttk.Entry(self.root, width=40)
        self.message_entry.grid(row=9, column=1, padx=10, pady=10, sticky="w")

        self.key_entry = ttk.Entry(self.root, width=5)
        self.key_entry1 = ttk.Entry(self.root, width=5)
        self.key_entry2 = ttk.Entry(self.root, width=5)
        self.key_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.key_entry1.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.key_entry2.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        self.turnover_entry = ttk.Entry(self.root, width=5)
        self.turnover_entry1 = ttk.Entry(self.root, width=5)
        self.turnover_entry2 = ttk.Entry(self.root, width=5)
        self.turnover_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        self.turnover_entry1.grid(row=1, column=2, padx=10, pady=10, sticky="w")
        self.turnover_entry2.grid(row=1, column=3, padx=10, pady=10, sticky="w")

        self.letter_entries = []
        for i in range(6):
            letter1_entry = ttk.Entry(self.root, width=5)
            letter1_entry.grid(row=2+i, column=1, padx=10, pady=5, sticky="w")
            self.letter_entries.append(letter1_entry)

            letter2_entry = ttk.Entry(self.root, width=5)
            letter2_entry.grid(row=2+i, column=2, padx=10, pady=5, sticky="e")
            self.letter_entries.append(letter2_entry)

        ttk.Label(self.root, text="Mensaje a cifrar:").grid(row=9, column=0, padx=10, pady=10, sticky="e")
        ttk.Label(self.root, text="Clave de configuración:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        ttk.Label(self.root, text="Turnover:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        ttk.Label(self.root, text="Cambio de números del clavijero:").grid(row=2, column=0, padx=10, pady=10, sticky="e")

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=40, height=5)
        self.result_text.grid(row=11, column=0, columnspan=2, pady=10)

        ttk.Button(self.root, text="Cifrar Mensaje", command=self.encrypt_message).grid(row=10, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text="Copiar Mensaje", command=self.copy_message).grid(row=12, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text="Cifrar Archivo", command=self.cifrar_archivo).grid(row=13, column=0, columnspan=2, pady=10)

    def validate_input(self, value):
        if value.isdigit() and 0 <= int(value) <= 255:
            return True
        else:
            return False

    def show_error(self, message):
        messagebox.showerror("Entrada inválida", message)

    def encrypt_message(self):
        mensaje = self.message_entry.get()
        mensaje_bytes= [ord(car) for car in mensaje]

        clave = [self.key_entry.get(), self.key_entry1.get(), self.key_entry2.get()]
        turnover = [self.turnover_entry.get(), self.turnover_entry1.get(), self.turnover_entry2.get()]

        if not all(self.validate_input(val) for val in clave + turnover):
            self.show_error("Todos los valores en clave de configuración y turnover deben ser números entre 0 y 255.")
            return

        clave = [int(val) for val in clave]
        turnover = [int(val) for val in turnover]

        try:
            lista_letra1 = [int(entry.get()) for entry in self.letter_entries[::2] if entry.get().isdigit() and self.validate_input(entry.get())]
            lista_letra2 = [int(entry.get()) for entry in self.letter_entries[1::2] if entry.get().isdigit() and self.validate_input(entry.get())]
        except ValueError:
            self.show_error("Todos los campos de cambio de números deben contener solo dígitos entre 0 y 255.")
            return

        if len(lista_letra1) != len(lista_letra2):
            self.show_error("Las listas de letras deben tener el mismo tamaño.")
            return

        mensaje_bytes_cif = self.enigma.enigma(mensaje_bytes, clave, turnover, lista_letra1, lista_letra2)
        resultado = ''.join(chr(num) for num in mensaje_bytes_cif)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, resultado)
        self.result_text.config(state=tk.DISABLED)

    def copy_message(self):
        self.root.clipboard_clear()
        message_content = self.result_text.get(1.0, tk.END).rstrip()
        self.root.clipboard_append(message_content)

    def cifrar_archivo(self):
        ruta_archivo = filedialog.askopenfilename(title="Seleccionar archivo", filetypes=(("Todos los archivos", "*.*"),))
        if ruta_archivo:
            datos = self.enigma.load_archivo(ruta_archivo)
            if datos is not None:
                clave = [self.key_entry.get(), self.key_entry1.get(), self.key_entry2.get()]
                turnover = [self.turnover_entry.get(), self.turnover_entry1.get(), self.turnover_entry2.get()]

                if not all(self.validate_input(val) for val in clave + turnover):
                    self.show_error("Todos los valores en clave de configuración y turnover deben ser números entre 0 y 255.")
                    return

                clave = [int(val) for val in clave]
                turnover = [int(val) for val in turnover]

                lista_letra1 = [int(entry.get()) for entry in self.letter_entries[::2] if entry.get().isdigit() and self.validate_input(entry.get())]
                lista_letra2 = [int(entry.get()) for entry in self.letter_entries[1::2] if entry.get().isdigit() and self.validate_input(entry.get())]

                if len(lista_letra1) != len(lista_letra2):
                    self.show_error("Las listas de letras deben tener el mismo tamaño.")
                    return

                ruta_archivo1 = filedialog.asksaveasfilename(title="Guardar archivo cifrado", filetypes=(("Archivos cifrados", "*.dat"), ("Todos los archivos", "*.*")), defaultextension=".dat")
                mensaje_bytes_cif = self.enigma.enigma(datos, clave, turnover, lista_letra1, lista_letra2)
                self.enigma.guardar_archivo_cifrado(mensaje_bytes_cif, ruta_archivo1)
            else:
                print("Error al cargar el archivo.")


def main():
    enigma_machine = Enigma()
    root = tk.Tk()
    app = EnigmaApp(root, enigma_machine)
    root.mainloop()


if __name__ == "__main__":
    main()
