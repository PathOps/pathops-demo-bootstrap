#!/usr/bin/env bash
set -e

OUTPUT="repo_dump.md"

echo "# Repository Export" > "$OUTPUT"
echo "" >> "$OUTPUT"

git ls-files | while read file; do
  if file --mime "$file" | grep -q text; then
    
    EXT="${file##*.}"
    
    echo "---" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "## 📄 $file" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "\`\`\`$EXT" >> "$OUTPUT"
    cat "$file" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "\`\`\`" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    
  fi
done

echo "Export completed → $OUTPUT"