import customtkinter as ctk
import random
import string
from tkinter import messagebox
import password_strength

ctk.set_appearance_mode("dark")

class PasswordHistoryFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.password_history = []
        self.scrollable_frame = ctk.CTkScrollableFrame(self)
        self.scrollable_frame.pack(fill="both", expand=True, pady=10, padx=10)

    def update_history(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        for password in self.password_history:
            password_frame = ctk.CTkFrame(self.scrollable_frame)
            password_frame.pack(fill="x", pady=5)
            password_label = ctk.CTkLabel(password_frame, text=password, font=("Arial", 12))
            password_label.pack(side="left", padx=10)
            copy_button = ctk.CTkButton(
                password_frame,
                text="Копіювати",
                width=100,
                command=lambda p=password: self.copy_history_password(p),
                fg_color="#4F3350",
                hover_color="#3D2740",
            )
            copy_button.pack(side="right", padx=10)

    def copy_history_password(self, password):
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        messagebox.showinfo("Успіх", f"Пароль скопійовано: {password}")

    def clear_history(self):
        self.password_history.clear()
        self.update_history()

class PasswordGenerator(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Генератор паролів")
        self.geometry("550x650")
        self.configure(bg="#8B688B")
        self.resizable(False, False)
        
        self.upper_var = ctk.BooleanVar()
        self.lower_var = ctk.BooleanVar()
        self.digits_var = ctk.BooleanVar()
        self.symbols_var = ctk.BooleanVar()
        self.special_symbols_var = ctk.BooleanVar()
        self.exclude_similar_var = ctk.BooleanVar()
        self.pass_length = 8
        self.pass_text = ""
        
        # всі фрейми
        self.password_frame = ctk.CTkFrame(self, fg_color="#644064")
        self.password_frame.pack(pady=10, padx=25, fill="x")
        
        self.length_frame = ctk.CTkFrame(self.password_frame, fg_color="#644064")
        self.length_frame.pack(side="left", padx=5, pady=5)
        
        self.option_frame = ctk.CTkFrame(self, fg_color="#644064")
        self.option_frame.pack(pady=(10, 0))
        
        self.history_frame = PasswordHistoryFrame(self, fg_color="#644064")      
        
        
        
        self.pass_strength_label = ctk.CTkLabel(
            self,
            text="",
            font=("Arial", 14),
            text_color="#F083B5",
        )
        self.pass_strength_label.pack(pady=10)
        self.length_up_button = ctk.CTkButton(
            self.length_frame,
            text="▲",
            width=35,
            height=20,
            fg_color="#4F3350",
            hover_color="#3D2740",
            command=self.increase_length,
        )
        self.length_up_button.pack()
        self.pass_length_var = ctk.StringVar(value=str(self.pass_length))
        self.length_entry = ctk.CTkEntry(
            self.length_frame,
            font=("Arial", 14),
            width=35,
            textvariable=self.pass_length_var,
            border_color="#4F3350",
        )
        self.length_entry.pack(pady=2)
        self.length_entry.bind("<FocusOut>", self.on_length_change)
        self.length_entry.bind("<Return>", self.on_length_change)
        
        self.length_down_button = ctk.CTkButton(
            self.length_frame,
            text="▼",
            width=35,
            height=20,
            fg_color="#4F3350",
            hover_color="#3D2740",
            command=self.decrease_length,
        )
        self.length_down_button.pack()
        
        self.password_entry = ctk.CTkEntry(
            self.password_frame,
            placeholder_text="Введіть або згенеруйте пароль...",
            width=350,
            font=("Arial", 14),
            border_color="#4F3350",
        )
        self.password_entry.pack(side="left", padx=5)
        self.copy_button = ctk.CTkButton(
            self.password_frame,
            text="Копіювати",
            fg_color="#4F3350",
            hover_color="#3D2740",
            width=100,
            command=self.copy_password,
        )
        self.copy_button.pack(side="right", padx=5)
        
        
        
        # ліва частина
        ctk.CTkCheckBox(
            self.option_frame, text="Великі літери", variable=self.upper_var, fg_color="#4F3350"
        ).grid(row=0, column=0, sticky="w", padx=20, pady=10)
        ctk.CTkCheckBox(
            self.option_frame, text="Малі літери", variable=self.lower_var, fg_color="#4F3350"
        ).grid(row=1, column=0, sticky="w", padx=20, pady=10)
        ctk.CTkCheckBox(
            self.option_frame, text="Цифри", variable=self.digits_var, fg_color="#4F3350"
        ).grid(row=2, column=0, sticky="w", padx=20, pady=10)
        
        # права частина
        ctk.CTkCheckBox(
            self.option_frame, text="Символи", variable=self.symbols_var, fg_color="#4F3350"
        ).grid(row=0, column=1, sticky="w", padx=20, pady=10)
        ctk.CTkCheckBox(
            self.option_frame, text="Спец-символи", variable=self.special_symbols_var, fg_color="#4F3350"
        ).grid(row=1, column=1, sticky="w", padx=20, pady=10)
        ctk.CTkCheckBox(
            self.option_frame,
            text="Виключити схожі символи",
            variable=self.exclude_similar_var,
            fg_color="#4F3350",
        ).grid(row=2, column=1, sticky="w", padx=20, pady=10)


        self.generate_button = ctk.CTkButton(
            self, text="Генерувати", width=250, fg_color="#4F3350", hover_color="#3D2740", command=self.generate_password
        )
        self.generate_button.pack(pady=5)
        self.check_strength_button = ctk.CTkButton(
            self, text="Перевірити надійність", width=250, fg_color="#4F3350", hover_color="#3D2740", command=self.check_strength
        )
        self.check_strength_button.pack(pady=5)
        self.clear_history_button = ctk.CTkButton(
            self, text="Очистити історію", width=250, fg_color="#4F3350", hover_color="#3D2740", command=self.clear_history
        )
        self.clear_history_button.pack(pady=5)
        # розміщення історії паролів
        self.history_frame.pack(pady=10, padx=25, fill="x")
        
        
    # функції
    def copy_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Помилка", "Пароль відсутній для копіювання.")
        else:
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Успіх", "Пароль скопійовано.")

    def generate_password(self):
        characters = ""
        if self.lower_var.get():
            characters += string.ascii_lowercase
        if self.upper_var.get():
            characters += string.ascii_uppercase
        if self.digits_var.get():
            characters += string.digits
        if self.symbols_var.get():
            characters += string.punctuation
        if self.special_symbols_var.get():
            characters += "!@#$%^&*()"
        if self.exclude_similar_var.get():
            characters = characters.translate(str.maketrans("", "", "Il1O0"))
        if not characters:
            messagebox.showerror("Помилка", "Будь ласка, виберіть хоча б один тип символів.")
        else:
            self.pass_text = "".join(random.choice(characters) for _ in range(self.pass_length))
            self.password_entry.delete(0, ctk.END)
            self.password_entry.insert(0, self.pass_text)
            self.history_frame.password_history.append(self.pass_text)
            self.history_frame.update_history()
            self.check_strength()

    def check_strength(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Помилка", "Введіть або згенеруйте пароль для перевірки.")
        else:
            self.update_strength_label(password)

    def update_strength_label(self, password):
        result = password_strength.calc_pass_strength(password)
        strength = result["strength"]
        self.pass_strength_label.configure(
            text=f"Надійність паролю: {strength}\n" + "\n".join(result["issues"]),
            text_color=result["color"],
            wraplength=300,
            justify="left",
        )
        self.update_idletasks()

    def clear_history(self):
        self.history_frame.clear_history()

    def on_length_change(self, event=None):
        value = self.pass_length_var.get()
        if value.isdigit():
            new_length = int(value)
            if 8 <= new_length <= 64:
                self.pass_length = new_length
            else:
                self.pass_length_var.set(str(self.pass_length))
        else:
            self.pass_length_var.set(str(self.pass_length))

    def increase_length(self):
        if self.pass_length < 64:
            self.pass_length += 1
            self.pass_length_var.set(str(self.pass_length))

    def decrease_length(self):
        if self.pass_length > 8:
            self.pass_length -= 1
            self.pass_length_var.set(str(self.pass_length))

app = PasswordGenerator()
app.mainloop()