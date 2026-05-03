#!/bin/sh

# Скрипт для бэкапа базы данных на Railway
# Использование: railway run sh backup.sh

BACKUP_DIR="/data/backups"
DB_PATH="/data/licenses.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/licenses_$TIMESTAMP.db"

# Создаем директорию для бэкапов
mkdir -p "$BACKUP_DIR"

# Проверяем существование базы данных
if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database not found at $DB_PATH"
    exit 1
fi

# Создаем бэкап
echo "Creating backup: $BACKUP_FILE"
cp "$DB_PATH" "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "Backup created successfully!"
    echo "File: $BACKUP_FILE"
    echo "Size: $(du -h $BACKUP_FILE | cut -f1)"
    
    # Удаляем старые бэкапы (старше 30 дней)
    find "$BACKUP_DIR" -name "licenses_*.db" -mtime +30 -delete
    echo "Old backups cleaned up (>30 days)"
    
    # Показываем список бэкапов
    echo ""
    echo "Available backups:"
    ls -lh "$BACKUP_DIR"
else
    echo "Error: Backup failed!"
    exit 1
fi
