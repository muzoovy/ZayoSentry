## Proje Yapısı

GitHub deposu yalnızca ZayoSentry'ye ait kaynak kodları barındırır. eBPF sensörünün derlenebilmesi için `libbpf-bootstrap` altyapısı kurulum aşamasında dışarıdan çekilir.

```text
ZayoSentry/
│
├── bpf-sensor/                  # Sadece projeye ait C kodları
│   ├── zayosentry.bpf.c
│   ├── zayosentry.c
│   └── zayosentry.h
│
├── dashboard/                    # Python arayüz motoru
│   ├── dashboard.py
│   ├── rules.yaml
│   ├── zayoelf.py                # Statik analiz aracım
│   │
│   ├── sandbox/
│   │   └── Dockerfile            # İzole ortam dosyası
│   │
│   └── reports/                  # CTI Rapor Çıktıları
│
├── bpfdoor_test.c      # BPFDoor-Benzeri Test Aracı
└── README.md

```

---

## Kurulum

ZayoSentry'nin BPF sensörü, derleme için resmi `libbpf-bootstrap` iskeletine ihtiyaç duyar. Aşağıdaki adımları sırasıyla uygulayarak projeyi herhangi bir Debian/Ubuntu sistemde sıfır hata ile kurabilirsiniz.

### 1. Bağımlılıkların Kurulması

```bash
#Sistem paketlerini güncelleyin ve gerekli derleme araçlarını kurun
sudo apt update
sudo apt install -y clang llvm libbpf-dev bpftool build-essential \
    python3 python3-pip podman libelf-dev zlib1g-dev linux-headers-$(uname -r)

#Python gereksinimlerini kurun
pip3 install pyyaml pyelftools --break-system-packages

```

### 2. ZayoSentry ve Altyapının İndirilmesi

```bash
#1. ZayoSentry reposunu klonlayın
git clone https://github.com/muzoovy/ZayoSentry
cd zayosentry

#2. Resmi libbpf-bootstrap iskeletini alt modülleriyle birlikte çekin
git clone --recursive https://github.com/libbpf/libbpf-bootstrap.git

```

### 3. BPF Sensörünün Derlenmesi ve Dashboard Kurulumu

ZayoSentry C kodlarını, derleme iskeletinin içine aktarıp derliyoruz:

```bash
#Kodlarımızı libbpf-bootstrap'in examples/c dizinine kopyalayalım
cp bpf-sensor/* libbpf-bootstrap/examples/c/


#Dashboard klasörümüzü libbpf-bootstrap'in ana dizinine taşıyalım

cp -r dashboard libbpf-bootstrap/

#Makefile'a ZayoSentry'yi ekleyip derleme işlemini başlatalım
cd libbpf-bootstrap/examples/c
sed -i 's/APPS =/APPS = zayosentry /' Makefile
make

#Başarılı derleme sonrasında ana dizine geri dönelim
cd ../../..

```

### 4. BPFDoor-Benzeri Test Aracının Derlenmesi (Opsiyonel)

Korelasyon motorunu test etmek için geliştirilen aracı derleyin:

```bash
gcc bpfdoor_test.c -o /tmp/bpfdoor_test
strip /tmp/bpfdoor_test #Sembolleri silmek için opsiyonel
upx /tmp/bpfdoor_test #Paketleme yapmak da opsiyonel olarak sistemde varsa

```

### 5. Çalıştırma

Anlık olarak sistemi izlemek için live modunda çalıştırabilirsiniz.

```bash
cd libbpf-bootstrap/dashboard
sudo python3 dashboard.py live

```

Belli bir şüpheli ELF dosyasını izole ortamda çalıştırıp statik ve dinamik analizden geçirmek için scan modunda çalıştırabilirsiniz..

```bash
sudo python3 dashboard.py scan /tmp/bpfdoor_test

```

Daha fazla yardım ve komut için ise help modunu kullanabilirsiniz.

```bash
sudo python3 dashboard.py --help

```
