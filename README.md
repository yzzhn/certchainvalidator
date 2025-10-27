# Inside Certificate Chains Beyond Public Issuers: Structure and Usage Analysis from a Campus Network
 
[![Paper DOI](https://img.shields.io/badge/DOI-10.1145%2F3730567.3764503-blue)](https://doi.org/10.1145/3730567.3764503)
[![Data](https://img.shields.io/badge/data-available-brightgreen)]()

---
## 📖 Overview

This repository contains the code, data, and supporting materials for the paper:

> **"Inside Certificate Chains Beyond Public Issuers: Structure and Usage Analysis from a Campus Network"**  
> *Hongying Dong, Yizhe Zhang, Hyeonmin Lee, Yixin Sun*  
> Published in *ACM Internet Measurement Conference (IMC) 2025*  
> [🔗 Read the paper here](https://doi.org/10.1145/3730567.3764503)

### 🧩 Abstract

This work presents our analysis on certificate chain study using a one-year campus network data collected at boarder router. Due IRB policy, we can not share the campus network traffic. This code repo shares the string-based certificate chain validator, the openssl connection data we collected in 2024, and the corresponding validation results. 

---

## 📁 Repository Structure

```

├── data/                   # Datasets
├── src/                    # Source code for experiments and models
├── notebooks/              # Jupyter notebooks for analysis or figures
├── requirements.txt        # Python dependencies
├── LICENSE
└── README.md

````

---

## Setup & Installation

You need `Jupyter Lab` or `Jupyter Notebook` to run the notebooks:

```bash
git clone https://github.com/yzzhn/certchainvalidator.git
cd certchainvalidator

pip install -r requirements.txt
````

---

## Data

We share the hybrid chain and non-public-DB chain data we collected in 2024. To use these data, please navigate to `data` folder, download the data in google drive and unzip the corresponding files.  

---

## Notebook

`chain_validator.ipynb` shares the demo code to use the validator to analyze string-based cert chain.


## 🧾 Citation

If you use this work, please cite:

```bibtex
update soon
```

---

## 📄 License

This project is licensed under the **Creative Commons Zero v1.0 Universal License** — see the [LICENSE](LICENSE) file for details.