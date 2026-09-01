import pandas as pd
import matplotlib.pyplot as plt

# 1. Завантажуємо результати з CSV
df = pd.read_csv('results.csv')

plt.figure(figsize=(9, 5))

# Назви та кольори для трьох зразків
samples = [
    (1, 'ASCII (Англійський текст)', '#1f77b4'),
    (2, 'Cyrillic (Український текст)', '#2ca02c'),
    (3, 'Numeric (Цифрові дані)', '#ff7f0e'),
    (4, 'Mix (Змішанні дані)', "#ca14ca")
]

# 2. Будуємо графік для кожного зразка
for sample_id, label, color in samples:
    sample_data = df[df['sample_id'] == sample_id]
    plt.plot(
        sample_data['round'], 
        sample_data['bit_difference_pct'], 
        marker='o', 
        linewidth=2, 
        label=label,
        color=color
    )

# 3. Лінія ідеального лавинного ефекту (50%)
plt.axhline(y=50, color='red', linestyle='--', alpha=0.7, label='Ідеальний ефект (50%)')

# 4. Оформлення
plt.title('Дослідження лавинного ефекту шифру Aegis (16 раундів)', fontsize=12, fontweight='bold')
plt.xlabel('Номер раунду мережі Фейстеля', fontsize=10)
plt.ylabel('Відсоток змінених бітів у шифротексті (%)', fontsize=10)
plt.xticks(range(1, 17))
plt.ylim(0, 100)
plt.grid(True, linestyle=':', alpha=0.6)
plt.legend(loc='lower right')

plt.tight_layout()

# Зберігаємо якісний графік для вставки в Word / LaTeX
plt.savefig('results.png', dpi=300)
print("✅ Графік успішно збережено як avalanche_effect_aegis.png")
plt.show()