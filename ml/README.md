# ML-модуль: детектор CSRF

Стековая обобщение (stacked generalisation): три ветки GBT → линейный мета-классификатор TensorFlow.

---

## Датасеты

| Датасет | Источник | Всего записей | CSRF (flag=y) | Безопасных | Доля CSRF |
|---------|----------|:-------------:|:-------------:|:----------:|:---------:|
| **mitch** | Академическая работа | 6 312 | 939 | 5 078 | 14.9% |
| **dwvm** | DVWA | 617 | 118 | 499 | 19.1% |
| **hackerone** | Раскрытия HackerOne | 6 102 | 2 559 | 3 543 | 41.9% |
| **Итого** | | **13 031** | **3 616** | **9 120** | **27.8%** |

### Признаки (52 колонки)

| Тип | Кол-во | Описание |
|-----|:------:|----------|
| Числовые | 5 | `numOfParams`, `numOfBools`, `numOfIds`, `numOfBlobs`, `reqLen` |
| Ключевые слова в пути/параметрах | 42 | 21 ключевое слово × 2 флага (`*InPath`, `*InParams`): create, add, set, delete, update, remove, friend, setting, password, token, change, action, pay, login, logout, post, comment, follow, subscribe, sign, view |
| HTTP-метод | 5 | `isGET`, `isPOST`, `isPUT`, `isDELETE`, `isOPTIONS` |

---

## Архитектура модели

```
Вход (52 признака)
        │
   ┌────┼────────────┐
   ▼    ▼            ▼
GBT₁  GBT₂        GBT₃
mitch dwvm    hackerone
   │    │            │
   └────┴────────────┘
           │
    [p_mitch, p_dwvm, p_h1]
           │
   Dense(1, sigmoid)  ← TF мета-классификатор
           │
    P(CSRF) ∈ [0, 1]
```

### Гиперпараметры GBT-ветвей

| Параметр | Значение |
|----------|----------|
| `n_estimators` | 300 |
| `learning_rate` | 0.05 |
| `max_depth` | 4 |
| `subsample` | 0.8 |
| `min_samples_leaf` | 5 |
| `max_features` | `"sqrt"` |
| Кросс-валидация | StratifiedKFold, k=5 |

### Гиперпараметры мета-классификатора

| Параметр | Значение |
|----------|----------|
| Архитектура | `Input(3) → Dense(1, sigmoid)` |
| Оптимизатор | Adam, lr=5×10⁻³ |
| Функция потерь | binary_crossentropy |
| Эпох макс. | 200 |
| Batch size | 128 |
| Early stopping | patience=15, monitor=val_auc |
| Train/val split | 80% / 20% (стратифицированный) |

---

## Метрики качества

Метрики получены на **полных датасетах** после загрузки сохранённых моделей (`ml/evaluate.py`).  
Ветки оцениваются на **собственном** датасете (in-sample); для out-of-fold оценки смотри лог обучения.

### GBT-ветви

| Метрика | mitch | dwvm | hackerone |
|---------|:-----:|:----:|:---------:|
| **AUC-ROC** | **0.9482** | **1.0000** | **1.0000** |
| Accuracy | 0.9285 | 0.9984 | 1.0000 |
| Precision | 0.8578 | 0.9916 | 1.0000 |
| Recall | 0.6230 | 1.0000 | 1.0000 |
| F1 | 0.7218 | 0.9958 | 1.0000 |
| TP / FP / TN / FN | 585/97/5276/354 | 118/1/498/0 | 2559/0/3543/0 |

### Мета-классификатор (все датасеты, n=13 031)

| Метрика | Значение |
|---------|:--------:|
| **AUC-ROC** | **0.9858** |
| Accuracy | 0.9565 |
| Precision | 0.9428 |
| Recall | 0.8977 |
| F1 | 0.9197 |
| TP / FP / TN / FN | 3246 / 197 / 9218 / 370 |

#### Classification report (мета-классификатор)

```
              precision    recall  f1-score   support

        safe       0.96      0.98      0.97      9415
        csrf       0.94      0.90      0.92      3616

    accuracy                           0.96     13031
   macro avg       0.95      0.94      0.94     13031
weighted avg       0.96      0.96      0.96     13031
```

---

## Задержка предсказания

Замеры проведены на CPU (Intel, без CUDA), n=200 вызовов.

| Режим | Значение |
|-------|----------|
| **Одиночный запрос** (end-to-end: 3×GBT + мета) | |
| — Mean | **33.01 мс** |
| — Median | **32.37 мс** |
| — P95 | **36.82 мс** |
| **Батч** (на одну запись при пакетном вызове) | |
| — mitch (6 312 записей) | 0.0021 мс/запись |
| — dwvm (617 записей) | 0.0017 мс/запись |
| — hackerone (6 102 записей) | 0.0015 мс/запись |
| — мета-классификатор (13 031) | 0.0173 мс/запись |

---

## Сохранённые модели

```
ml/saved_models/
  branch_mitch.pkl       # GBT, ~479 KB
  branch_dwvm.pkl        # GBT, ~373 KB
  branch_hackerone.pkl   # GBT, ~560 KB
  meta_classifier.keras  # TF/Keras, ~18 KB
```

## Запуск оценки

```bash
# из корня проекта:
.venv/bin/python ml/evaluate.py
```

## Переобучение моделей

```bash
.venv/bin/python ml/model.py
```
