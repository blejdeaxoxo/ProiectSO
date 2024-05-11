file=$1

chmod +r "$file"

content=$(cat "$file")
wc_output=$(echo "$content" | wc -l -w -c)

line_count=$(echo "$wc_output" | awk '{print $1}')
word_count=$(echo "$wc_output" | awk '{print $2}')
char_count=$(echo "$wc_output" | awk '{print $3}')

if [ "$line_count" -lt 3 ] && [ "$word_count" -gt 1000 ] && [ "$char_count" -gt 2000 ]; then
    if grep -qP '[^\x00-\x7F]' "$file" || grep -qiE "corrupted|dangerous|risk|attack|malware|malicious" "$file"; then
        echo "$file"
    else echo "SAFE"
    fi
else echo "SAFE"
fi

chmod 000 "$file"

exit 0
