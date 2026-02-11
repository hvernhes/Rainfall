#include <cstdlib>
#include <cstring>

class N {
private:
    int value;
    char annotation[100];

public:
    // Constructeur
    N(int n) {
        this->value = n;
    }

    // Méthode vulnérable - pas de vérification de taille
    void setAnnotation(char *str) {
        size_t len = strlen(str);
        memcpy(this->annotation, str, len);
    }

    // Opérateur surchargé (méthode virtuelle)
    virtual int operator+(N &other) {
        return this->value + other.value;
    }

    // Opérateur surchargé (méthode virtuelle)
    virtual int operator-(N &other) {
        return this->value - other.value;
    }
};

int main(int argc, char **argv) {
    if (argc < 2) {
        _exit(1);
    }

    // Allocation de deux objets N sur la heap
    N *obj1 = new N(5);
    N *obj2 = new N(6);

    // Copie argv[1] dans obj1 - VULNÉRABILITÉ
    obj1->setAnnotation(argv[1]);

    // Appel de méthode virtuelle via vtable
    // Si la vtable de obj2 a été corrompue, exécution détournée
    (*obj2) + (*obj1);

    return 0;
}