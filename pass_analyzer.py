import customtkinter as ctk
import string
import random
import re

class PasswordGeneratorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Add the heading at the top of the app
        self.header_label = ctk.CTkLabel(
            self, 
            text="Password Analyzer", 
            font=ctk.CTkFont(family="JetBrains Mono", weight = "bold", size=28),
            fg_color="#2b2b2b",  # Background color for the header
            text_color="white",  # Text color for contrast
            corner_radius=8,
            anchor="center",
            height=60
        )
        self.header_label.pack(side="top", fill="x", padx=20, pady=(20, 0))

        self.title("Password Analyzer")
        self.geometry("1200x800")
        self.resizable(True, True)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.custom_font = ctk.CTkFont(family="JetBrains Mono", size=14)
        self.bold_font = ctk.CTkFont(family="JetBrains Mono Bold", size=15)
        
        # Main Frame
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        
        # Password Evaluation Frame
        self.eval_frame = ctk.CTkFrame(self, corner_radius=10)
        self.eval_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        # Password Evaluation Frame Widgets
        self.eval_title_label = ctk.CTkLabel(self.eval_frame, text="Password Evaluation", font=ctk.CTkFont(family="JetBrains Mono", size=20))
        self.eval_strength_label = ctk.CTkLabel(self.eval_frame, text="Strength: ", font=ctk.CTkFont(family="JetBrains Mono", size=15))
        self.eval_weaknesses_label = ctk.CTkLabel(self.eval_frame, text="Weaknesses: ", font=ctk.CTkFont(family="JetBrains Mono", size=15))
        self.eval_recommendations_label = ctk.CTkLabel(self.eval_frame, text="Recommendations: ", font=ctk.CTkFont(family="JetBrains Mono", size=15))
        # self.eval_title_label = ctk.CTkLabel(self.eval_frame, text="Password Evaluation", font=ctk.CTkFont(family="JetBrains Mono", size=20))
        # self.eval_strength_label = ctk.CTkLabel(self.eval_frame, text="Strength: ", font=self.bold_font)
        # self.eval_weaknesses_label = ctk.CTkLabel(self.eval_frame, text="Weaknesses: ", font=self.bold_font, wraplength=400)
        # self.eval_recommendations_label = ctk.CTkLabel(self.eval_frame, text="Recommendations: ", font=self.bold_font, wraplength=400)
        
        self.eval_title_label.pack(pady=10, fill="x")
        self.eval_strength_label.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.eval_weaknesses_label.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.eval_recommendations_label.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        
        # Main Frame Widgets
        self.title_label = ctk.CTkLabel(self.main_frame, text="Password Generator", font=ctk.CTkFont(family="JetBrains Mono", size=24))
        self.password_label = ctk.CTkLabel(self.main_frame, text="ARnGp5wt1gu8S16x", font=ctk.CTkFont(family="JetBrains Mono", size=16))
        
        self.password_type_var = ctk.StringVar(value="Password")
        self.password_radio = ctk.CTkRadioButton(self.main_frame, text="Password", variable=self.password_type_var, value="Password", font=self.custom_font, command=self.update_controls)
        self.enter_password_radio = ctk.CTkRadioButton(self.main_frame, text="Enter Password", variable=self.password_type_var, value="Enter Password", font=self.custom_font, command=self.update_controls)
        
        self.length_slider = ctk.CTkSlider(self.main_frame, from_=3, to=30, number_of_steps=27, command=self.update_length_value)
        self.length_value_label = ctk.CTkLabel(self.main_frame, text="18", font=self.custom_font)
        
        self.uppercase_var = ctk.BooleanVar(value=True)
        self.lowercase_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.special_var = ctk.BooleanVar(value=True)
        self.ambiguous_var = ctk.BooleanVar(value=False)
        
        self.uppercase_checkbox = ctk.CTkCheckBox(self.main_frame, text="A-Z", variable=self.uppercase_var, font=self.custom_font)
        self.lowercase_checkbox = ctk.CTkCheckBox(self.main_frame, text="a-z", variable=self.lowercase_var, font=self.custom_font)
        self.digits_checkbox = ctk.CTkCheckBox(self.main_frame, text="0-9", variable=self.digits_var, font=self.custom_font)
        self.special_checkbox = ctk.CTkCheckBox(self.main_frame, text="@#$%^&*", variable=self.special_var, font=self.custom_font)
        self.ambiguous_checkbox = ctk.CTkCheckBox(self.main_frame, text="Avoid ambiguous characters", variable=self.ambiguous_var, font=self.custom_font)
        
        self.user_password_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Enter your password", font=self.custom_font, width=200, state="normal")
        
        self.generate_button = ctk.CTkButton(self.main_frame, text="Generate/Evaluate", command=self.generate_button_clicked, font=self.custom_font)
        
        self.title_label.pack(pady=20, fill="x")
        self.password_label.pack(pady=10, fill="x")
        
        self.password_radio.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.enter_password_radio.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        
        self.length_slider.pack(pady=10, fill="x", padx=(20, 0))
        self.length_value_label.pack(pady=5, fill="x", padx=(20, 0))
        
        self.uppercase_checkbox.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.lowercase_checkbox.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.digits_checkbox.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.special_checkbox.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        self.ambiguous_checkbox.pack(pady=5, anchor="w", padx=(20, 0), fill="x")
        
        self.user_password_entry.pack(pady=5, fill="x", padx=(20, 0))
        
        self.generate_button.pack(pady=20, fill="x", padx=(20, 0))
        
        self.length_slider.set(18)
        
        self.update_controls()
    
    def update_length_value(self, value):
        self.length_value_label.configure(text=f"{int(value)}")
    
    def update_controls(self):
        password_type = self.password_type_var.get()
        if password_type == "Enter Password":
            self.length_slider.configure(state="disabled")
            self.uppercase_checkbox.configure(state="disabled")
            self.lowercase_checkbox.configure(state="disabled")
            self.digits_checkbox.configure(state="disabled")
            self.special_checkbox.configure(state="disabled")
            self.ambiguous_checkbox.configure(state="disabled")
            self.user_password_entry.configure(state="normal")
        else:
            self.length_slider.configure(state="normal")
            self.uppercase_checkbox.configure(state="normal")
            self.lowercase_checkbox.configure(state="normal")
            self.digits_checkbox.configure(state="normal")
            self.special_checkbox.configure(state="normal")
            self.ambiguous_checkbox.configure(state="normal")
            self.user_password_entry.configure(state="disabled")
    
    def generate_password(self):
        length = int(self.length_slider.get())
        password_type = self.password_type_var.get()
        
        characters = ""
        if self.uppercase_var.get():
            characters += string.ascii_uppercase
        if self.lowercase_var.get():
            characters += string.ascii_lowercase
        if self.digits_var.get():
            characters += string.digits
        if self.special_var.get():
            characters += string.punctuation
        if self.ambiguous_var.get():
            characters = characters.replace('l', '').replace('I', '').replace('1', '').replace('o', '').replace('O', '').replace('0', '')
        
        if not characters:
            return None
        
        password = ''.join(random.choice(characters) for _ in range(length))
        
        # Ensure password has at least one of each character type
        if self.uppercase_var.get() and not any(char.isupper() for char in password):
            password = random.choice(string.ascii_uppercase) + password[1:]
        if self.lowercase_var.get() and not any(char.islower() for char in password):
            password = random.choice(string.ascii_lowercase) + password[1:]
        if self.digits_var.get() and not any(char.isdigit() for char in password):
            password = random.choice(string.digits) + password[1:]
        if self.special_var.get() and not any(char in string.punctuation for char in password):
            password = random.choice(string.punctuation) + password[1:]
        
        return password
    
    def generate_button_clicked(self):
        password_type = self.password_type_var.get()
        if password_type == "Enter Password":
            password = self.user_password_entry.get()
            if password:
                self.password_label.configure(text=password)
                self.evaluate_password(password)
            else:
                self.password_label.configure(text="Please enter a password")
        else:
            password = self.generate_password()
            if password is not None:
                self.password_label.configure(text=password)
                self.evaluate_password(password)
            else:
                self.password_label.configure(text="Please select at least one character type")
    
    def evaluate_password(self, password):
        strength = 0
        weaknesses = []
        recommendations = []
        
        # Check password length
        if len(password) < 8:
            weaknesses.append("•Password is too short")
            recommendations.append("•Use a password with at least 8 characters")
        elif len(password) >= 12:
            strength += 1
        else:
            strength += 0.5
        
        # Check password complexity
        if not any(char.isupper() for char in password):
            weaknesses.append("•Password does not contain uppercase letters")
            recommendations.append("•Use a password with at least one uppercase letter")
        else:
            strength += 1
        
        if not any(char.islower() for char in password):
            weaknesses.append("•Password does not contain lowercase letters")
            recommendations.append("•Use a password with at least one lowercase letter")
        else:
            strength += 1
        
        if not any(char.isdigit() for char in password):
            weaknesses.append("•Password does not contain digits")
            recommendations.append("•Use a password with at least one digit")
        else:
            strength += 1
        
        if not any(char in string.punctuation for char in password):
            weaknesses.append("•Password does not contain special characters")
            recommendations.append("•Use a password with at least one special character")
        else:
            strength += 1
        
        # Check password for common patterns
        # common_patterns = ["abc", "123", "qwerty"]
        common_patterns = [
                                "abc", "123", "qwerty", "abcd", "1234", "asdf", "zxcvbn", 
                                "qwertyuiop", "asdfghjkl", "1111", "aaaa", "passwordpassword", 
                                "123123", "111111", "qwertyqwerty", "abcd1234", "password123", 
                                "welcome1", "qwerty123", "abc1234", "qwerty1", "2020", "2024", 
                                "1990", "202020", "19991999", "2000", "iloveyou", "sunshine", 
                                "admin", "letmein", "monkey", "princess", "1qaz2wsx", "123qwe", 
                                "zxcvbnm", "qwerty123", "1qaz2wsx", "1234@abcd", "@qwerty123", 
                                "abcd$123", "zyxwvuts", "9876", "54321", "321", "987654321", 
                                "password1", "letmein123", "welcome123", "qwerty1234", "iloveyou1", 
                                "mysecurepassword", "123qwerty", "sunshine123", "chocolate1", 
                                "love1234", "birthday2024", "01/01/2024", "01012000", "january2024", 
                                "2023birthday", "12december", "!@#$%^&*", "qwerty!@#", "12345!@", 
                                "1qaz@WSX", "QWERTY@123", "987654", "2468", "13579", "5555", 
                                "777777", "333333", "8888", "computer", "football", "baseball", 
                                "apple123", "starwars", "pokemon123", "princess1", "batman", 
                                "dragon123", "superman1", "qazwsx", "abcde", "fghij", "klmno", 
                                "pqrst", "uvwxyz", "password1!", "1234abcd!", "qwerty@2024", 
                                "abc123!", "letmein2024", "love!2024", "user1234", "admin2024", 
                                "guest123", "testuser1", "admin1"
                            ]

        for pattern in common_patterns:
            if pattern in password.lower():
                weaknesses.append(f"•Password contains common pattern '{pattern}'")
                recommendations.append(f"•Avoid using common patterns like '{pattern}'")
        
        # Evaluate password strength
        if strength >= 5:
            self.eval_strength_label.configure(text="Strength: Very Strong")
        elif strength >= 4:
            self.eval_strength_label.configure(text="Strength: Strong")
        elif strength >= 3:
            self.eval_strength_label.configure(text="Strength: Medium")
        elif strength >= 2:
            self.eval_strength_label.configure(text="Strength: Weak")
        else:
            self.eval_strength_label.configure(text="Strength: Very Weak")
        
        # Display weaknesses and recommendations
        weaknesses_text = "\n".join(weaknesses)
        recommendations_text = "\n".join(recommendations)
        self.eval_weaknesses_label.configure(text=f"Weaknesses:\n{weaknesses_text}")
        self.eval_recommendations_label.configure(text=f"Recommendations:\n{recommendations_text}")

if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.mainloop()