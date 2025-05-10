import os
import hashlib
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import imagehash

def strip_exif(filepath):
    try:
        img = Image.open(filepath)
        data = list(img.getdata())
        img_without_exif = Image.new(img.mode, img.size)
        img_without_exif.putdata(data)
        return img_without_exif
    except Exception as e:
        print(f"Ошибка очистки метаданных {filepath}: {e}")
        return None

def get_cleaned_file_hash(filepath):
    cleaned_img = strip_exif(filepath)
    if cleaned_img:
        hasher = hashlib.md5()
        cleaned_img.save(filepath + ".temp", "JPEG")
        with open(filepath + ".temp", 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        os.remove(filepath + ".temp")
        return hasher.hexdigest()
    return None

def get_file_hash(filepath):
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Ошибка чтения {filepath}: {e}")
        return None

def get_phash(filepath, size=(32, 32)):
    """Вычисляет perceptual hash файла"""
    try:
        img = Image.open(filepath).convert("RGB").resize(size)
        phash = str(imagehash.phash(img))
        return phash
    except Exception as e:
        print(f"Ошибка чтения {filepath}: {e}")
        return None

def find_similar_images(folder_path, threshold=10):
    hash_groups = {}

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                filepath = os.path.join(root, filename)
                file_hash = get_phash(filepath)

                if file_hash:
                    matched = False
                    for existing_hash in hash_groups:
                        if abs(imagehash.hex_to_hash(existing_hash) - imagehash.hex_to_hash(file_hash)) <= threshold:
                            hash_groups[existing_hash].append(filepath)
                            matched = True
                            break
                    if not matched:
                        hash_groups[file_hash] = [filepath]

    # Оставляем только группы с более чем одним файлом
    return {h: files for h, files in hash_groups.items() if len(files) > 1}

def get_file_size(filepath):
    try:
        return os.path.getsize(filepath)
    except Exception:
        return 0

def find_duplicates(folder_path):
    hashes = {}
    duplicates = []

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                filepath = os.path.join(root, filename)
                file_hash = get_file_hash(filepath)

                if file_hash:
                    if file_hash in hashes:
                        duplicates.append((filepath, hashes[file_hash]))
                    else:
                        hashes[file_hash] = filepath

    return duplicates


class DuplicateApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Поиск дубликатов фото")
        self.root.geometry("800x600")

        self.label = Label(root, text="Выберите папку для поиска дубликатов", font=("Arial", 14))
        self.label.pack(pady=20)

        self.select_button = Button(root, text="Выбрать папку", command=self.select_folder)
        self.select_button.pack(pady=10)

        self.about_button = Button(self.root, text="О программе", command=self.show_about)
        self.about_button.pack(pady=5)

        self.result_canvas = Canvas(root)
        self.scrollbar = Scrollbar(root, orient="vertical", command=self.result_canvas.yview)
        self.scrollable_frame = Frame(self.result_canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.result_canvas.configure(scrollregion=self.result_canvas.bbox("all"))
        )

        self.result_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.result_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.result_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

    def show_about(self):
        about_text = (
            "Сканер дублирующих и похожих фото\n"
            "Версия: 5.0\n"
            "Автор: krik\n"
            "Email: krik@bee-media.ru\n"
            "Программа помогает находить дубликаты и похожие фото,\n"
            "позволяет удалять их, освобождая место на диске.\n"
            "Поддерживает MD5-хэши и perceptual hash (phash/dhash/whash)."
        )
        messagebox.showinfo("О программе", about_text)

    def delete_all_duplicates(self, files, selected_original_var, widgets_list):
        original = selected_original_var.get()
        to_delete = [f for f in files if f != original]
        if not to_delete:
            messagebox.showinfo("Нечего удалять", "Все файлы, кроме оригинала, уже удалены.")
            return
        confirm = messagebox.askyesno("Подтверждение",
                                      f"Удалить {len(to_delete)} файлов?\nОстанется только:\n{original}")
        if confirm:
            for filepath in to_delete:
                try:
                    os.remove(filepath)
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось удалить файл:\n{filepath}\n\n{str(e)}")
            for widget in widgets_list:
                widget.pack_forget()
            messagebox.showinfo("Успех", f"Удалено {len(to_delete)} дубликатов.")

    def delete_and_remove(self, filepath, frame_widget):
        if messagebox.askyesno("Подтверждение", f"Удалить файл:\n{filepath}?"):
            try:
                os.remove(filepath)
                frame_widget.pack_forget()
                messagebox.showinfo("Успех", f"Файл удален:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось удалить файл:\n{filepath}\n\n{str(e)}")

    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"

    def get_file_hash(filepath):
        """Вычисляет MD5 хэш файла"""
        hasher = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                buf = f.read(65536)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(65536)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Ошибка чтения {filepath}: {e}")
            return None

    def find_duplicates_by_md5(self, folder_path):
        hashes = {}
        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                    filepath = os.path.join(root, filename)
                    file_hash = get_file_hash(filepath)
                    if file_hash:
                        if file_hash in hashes:
                            hashes[file_hash].append(filepath)
                        else:
                            hashes[file_hash] = [filepath]
        return {h: files for h, files in hashes.items() if len(files) > 1}

    def show_duplicate_groups(self, groups):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        if not groups:
            Label(self.scrollable_frame, text="Дубликатов не найдено.", font=("Arial", 12)).pack(pady=20)
            return

        total_free_space = 0

        for idx, (file_hash, files) in enumerate(groups.items()):
            group_frame = Frame(self.scrollable_frame, bd=2, relief="groove")
            group_frame.pack(padx=10, pady=10, fill="x")

            Label(group_frame, text=f"Группа {idx + 1} ({len(files)} файлов)", font=("Arial", 12, "bold")).pack(
                anchor="w")

            file_data = []
            for filepath in files:
                size = get_file_size(filepath)
                file_data.append((filepath, size))

            free_space = sum(size for _, size in file_data[1:])
            total_free_space += free_space

            Label(group_frame, text=f"Можно освободить: {self.format_size(free_space)}", fg="green").pack(anchor="w",
                                                                                                          padx=5)

            photos_container = Frame(group_frame)
            photos_container.pack(fill="x", padx=5, pady=5)

            selected_original = StringVar(value=file_data[0][0])
            group_widgets = []

            row_frame = Frame(photos_container)
            row_frame.pack(fill="x")

            for i, (filepath, size) in enumerate(file_data):
                if i % 3 == 0 and i != 0:
                    row_frame = Frame(photos_container)
                    row_frame.pack(fill="x")

                frame = Frame(row_frame)
                frame.pack(side="left", padx=15, pady=5)
                group_widgets.append(frame)

                photo_holder = Frame(frame)
                photo_holder.pack()

                try:
                    img = Image.open(filepath).resize((160, 160))
                    img_tk = ImageTk.PhotoImage(img)
                    lbl = Label(photo_holder, image=img_tk)
                    lbl.image = img_tk
                    lbl.pack()

                    def on_click(event, label=lbl, path=filepath):
                        big_img = Image.open(path).resize((240, 240))
                        big_img_tk = ImageTk.PhotoImage(big_img)
                        label.configure(image=big_img_tk)
                        label.image = big_img_tk

                    def on_double_click(event, path=filepath):
                        self.show_full_size(path)

                    lbl.bind("<Button-1>", on_click)
                    lbl.bind("<Double-Button-1>", on_double_click)
                except Exception:
                    Label(frame, text="❌ Не загружено").pack()

                Label(frame, text=os.path.basename(filepath), font=("Arial", 9), wraplength=160,
                      justify="center").pack()
                Label(frame, text=self.format_size(size), font=("Arial", 8), fg="gray").pack()
                Radiobutton(frame, text="Оригинал", variable=selected_original, value=filepath,
                            font=("Arial", 9)).pack()
                Button(frame, text="🗑 Удалить", width=10,
                       command=lambda f=filepath, p=frame: self.delete_and_remove(f, p)).pack(pady=5)

            delete_all_btn = Button(group_frame, text="🧹 Удалить все копии", bg="red", fg="white",
                                    command=lambda fs=[f[0] for f in file_data], sv=selected_original,
                                                   widgets=group_widgets: self.delete_all_duplicates(fs, sv, widgets))
            delete_all_btn.pack(pady=5)

        summary_frame = Frame(self.scrollable_frame, bd=2, relief="ridge", bg="lightyellow")
        summary_frame.pack(padx=10, pady=10, fill="x")
        Label(summary_frame, text="Общий объём для освобождения:", font=("Arial", 12, "bold"), bg="lightyellow").pack(
            anchor="w")
        Label(summary_frame, text=self.format_size(total_free_space), font=("Arial", 14), fg="green",
              bg="lightyellow").pack(anchor="w", padx=10, pady=5)

    def select_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку с фотографиями")
        if folder:
            self.label.config(text=f"Идёт сканирование: {folder}")
            self.root.update()

            duplicates = find_similar_images(folder)
            self.show_duplicate_groups(duplicates)
            messagebox.showinfo("Готово", "Сканирование завершено!")

    def show_full_size(self, filepath):
        try:
            img = Image.open(filepath)
            img.thumbnail((1000, 1000))  # Максимальный размер окна
            img_tk = ImageTk.PhotoImage(img)

            top = Toplevel(self.root)
            top.title(f"Полный размер: {os.path.basename(filepath)}")

            label = Label(top, image=img_tk)
            label.image = img_tk
            label.pack()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть фото:\n{filepath}\n\n{str(e)}")

    def show_duplicates(self, duplicates):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        if not duplicates:
            Label(self.scrollable_frame, text="Дубликатов не найдено.", font=("Arial", 12)).pack(pady=20)
            return

        for i, (file1, file2) in enumerate(duplicates[:50], 1):  # ограничение до 50 пар
            frame = Frame(self.scrollable_frame, bd=2, relief="groove")
            frame.pack(padx=10, pady=5, fill="x")

            Label(frame, text=f"{i}. Дубликат:", font=("Arial", 10, "bold")).pack(anchor="w")

            # Фото 1
            try:
                img1 = Image.open(file1).resize((100, 100))
                img1_tk = ImageTk.PhotoImage(img1)
                lbl1 = Label(frame, image=img1_tk)
                lbl1.image = img1_tk
                lbl1.pack(side="left", padx=10)
                Label(frame, text=os.path.basename(file1), fg="blue").pack(side="left")
            except Exception:
                Label(frame, text="❌ Не удалось загрузить фото 1").pack(side="left")

            # Фото 2
            try:
                img2 = Image.open(file2).resize((100, 100))
                img2_tk = ImageTk.PhotoImage(img2)
                lbl2 = Label(frame, image=img2_tk)
                lbl2.image = img2_tk
                lbl2.pack(side="left", padx=10)
                Label(frame, text=os.path.basename(file2), fg="blue").pack(side="left")
            except Exception:
                Label(frame, text="❌ Не удалось загрузить фото 2").pack(side="left")

            Label(frame, text=file1, font=("Arial", 8), fg="gray").pack(anchor="w")
            Label(frame, text=file2, font=("Arial", 8), fg="gray").pack(anchor="w")

            btn_frame = Frame(frame)
            btn_frame.pack(pady=5, anchor="e")

            Button(btn_frame, text="🗑 Удалить дубликат", width=18,
                   command=lambda f=file2: self.delete_file(f, frame)).pack(side="left", padx=5)

            Button(btn_frame, text="🗑 Оставить оригинал", width=18,
                   command=lambda f=file1: self.delete_file(f, frame)).pack(side="left", padx=5)

    def delete_file(self, filepath, frame_widget):
        if messagebox.askyesno("Подтверждение", f"Удалить файл:\n{filepath}?"):
            try:
                os.remove(filepath)
                frame_widget.pack_forget()
                messagebox.showinfo("Успех", f"Файл удален:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось удалить файл:\n{filepath}\n\n{str(e)}")


if __name__ == "__main__":
    root = Tk()
    app = DuplicateApp(root)
    root.mainloop()