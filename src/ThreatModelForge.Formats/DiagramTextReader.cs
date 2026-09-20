namespace ThreatModelForge.Formats
{
    using System;
    using System.IO;
    using System.Text;

    /// <summary>A bounded cursor for the supported text-diagram grammars.</summary>
    internal sealed class DiagramTextReader
    {
        private const int MaxDocumentBytes = 8 * 1024 * 1024;
        private const int MaxTokenLength = 2048;
        private readonly string text;
        private readonly bool dot;
        private int position;

        /// <summary>Initializes a new instance of the <see cref="DiagramTextReader"/> class.</summary>
        /// <param name="text">Source text.</param>
        /// <param name="dot">Whether to use DOT comments and identifiers.</param>
        internal DiagramTextReader(string text, bool dot)
        {
            this.text = text.Replace("\r\n", "\n").Replace('\r', '\n').TrimStart('\uFEFF');
            this.dot = dot;
        }

        /// <summary>Gets a value indicating whether the input is exhausted.</summary>
        internal bool End => this.position == this.text.Length;

        /// <summary>Gets the current character, or a zero sentinel at the end.</summary>
        internal char Current => this.End ? '\0' : this.text[this.position];

        /// <summary>Reads bounded, strictly decoded UTF-8 without closing the input.</summary>
        /// <param name="stream">The source stream.</param>
        /// <returns>The decoded source.</returns>
        internal static string ReadText(Stream stream)
        {
            _ = stream ?? throw new ArgumentNullException(nameof(stream));
            if (stream.CanSeek && stream.Length - stream.Position > MaxDocumentBytes)
            {
                throw new InvalidDataException("Text diagram import is limited to 8 MiB.");
            }

            using MemoryStream buffer = new MemoryStream();
            byte[] chunk = new byte[4096];
            int count;
            while ((count = stream.Read(chunk, 0, chunk.Length)) != 0)
            {
                if (buffer.Length + count > MaxDocumentBytes)
                {
                    throw new InvalidDataException("Text diagram import is limited to 8 MiB.");
                }

                buffer.Write(chunk, 0, count);
            }

            try
            {
                return new UTF8Encoding(false, true).GetString(buffer.ToArray());
            }
            catch (DecoderFallbackException exception)
            {
                throw new InvalidDataException("Text diagrams must be valid UTF-8.", exception);
            }
        }

        /// <summary>Recognizes a diagram header without changing the stream position.</summary>
        /// <param name="stream">The seekable source stream.</param>
        /// <param name="dot">Whether to recognize DOT instead of Mermaid.</param>
        /// <returns>Whether a supported format header is present.</returns>
        internal static bool Sniff(Stream stream, bool dot)
        {
            _ = stream ?? throw new ArgumentNullException(nameof(stream));
            if (!stream.CanSeek)
            {
                throw new NotSupportedException("Content sniffing requires a seekable stream.");
            }

            long position = stream.Position;
            try
            {
                byte[] prefix = new byte[4096];
                int length = 0;
                int count;
                while (length < prefix.Length && (count = stream.Read(prefix, length, prefix.Length - length)) != 0)
                {
                    length += count;
                }

                DiagramTextReader reader = new DiagramTextReader(Encoding.UTF8.GetString(prefix, 0, length), dot);
                reader.SkipSpace(true);
                if (dot && (reader.Word("digraph") || reader.Word("strict")))
                {
                    return true;
                }

                if (!dot && (reader.Word("flowchart") || reader.Take("```mermaid")))
                {
                    return true;
                }

                if (!reader.Word("graph"))
                {
                    return false;
                }

                reader.SkipSpace(true);
                if (!reader.At("{"))
                {
                    reader.Identifier();
                    reader.SkipSpace(true);
                }

                return dot == reader.At("{");
            }
            catch (InvalidDataException)
            {
                return false;
            }
            finally
            {
                stream.Position = position;
            }
        }

        /// <summary>Tests the next literal without consuming it.</summary>
        /// <param name="value">The expected literal.</param>
        /// <returns>Whether the literal matches.</returns>
        internal bool At(string value)
        {
            return this.position + value.Length <= this.text.Length
                && string.CompareOrdinal(this.text, this.position, value, 0, value.Length) == 0;
        }

        /// <summary>Consumes a literal when present.</summary>
        /// <param name="value">The expected literal.</param>
        /// <returns>Whether the literal was consumed.</returns>
        internal bool Take(string value)
        {
            if (!this.At(value))
            {
                return false;
            }

            this.position += value.Length;
            return true;
        }

        /// <summary>Consumes a keyword only at an identifier boundary.</summary>
        /// <param name="value">The expected keyword.</param>
        /// <returns>Whether the keyword was consumed.</returns>
        internal bool Word(string value)
        {
            int end = this.position + value.Length;
            bool matches = end <= this.text.Length && string.Compare(this.text, this.position, value, 0, value.Length, this.dot ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) == 0;
            if (!matches || (end < this.text.Length && IsIdentifierCharacter(this.text[end])))
            {
                return false;
            }

            this.position = end;
            return true;
        }

        /// <summary>Consumes a required literal or reports its source location.</summary>
        /// <param name="value">The required literal.</param>
        internal void Expect(string value)
        {
            if (!this.Take(value))
            {
                throw this.Error($"Expected '{value}', found {this.DescribeCurrent()}.");
            }
        }

        /// <summary>Skips whitespace and comments without dropping Mermaid directives.</summary>
        /// <param name="newlines">Whether to cross statement-ending newlines.</param>
        internal void SkipSpace(bool newlines = false)
        {
            while (!this.End)
            {
                if (char.IsWhiteSpace(this.Current) && (newlines || this.Current != '\n'))
                {
                    this.position++;
                }
                else if ((this.dot && this.At("//")) || (!this.dot && this.At("%%")))
                {
                    if (!this.dot && this.At("%%{"))
                    {
                        throw this.Error("Unsupported Mermaid initialization directive '%%{'.");
                    }

                    while (!this.End && this.Current != '\n')
                    {
                        this.position++;
                    }
                }
                else if (this.dot && this.Take("/*"))
                {
                    while (!this.End && !this.At("*/"))
                    {
                        this.position++;
                    }

                    this.Expect("*/");
                }
                else
                {
                    break;
                }
            }
        }

        /// <summary>Reads a source identifier or DOT quoted value.</summary>
        /// <param name="label">Whether to decode label-specific escapes.</param>
        /// <param name="allowKeyword">Whether a DOT statement keyword may be returned.</param>
        /// <returns>The source value.</returns>
        internal string Identifier(bool label = false, bool allowKeyword = false)
        {
            if (this.dot && this.Current == '"')
            {
            return this.Quoted(label);
            }

            int start = this.position;
            while (!this.End && IsIdentifierCharacter(this.Current)
                && !this.At("--") && !this.At("->") && !this.At(".->") && (this.dot || !this.At("-.")))
            {
                this.position++;
            }

            if (this.position == start)
            {
                throw this.Error($"Expected a source identifier, found {this.DescribeCurrent()}.");
            }

            string value = this.Token(start);
            if (this.dot && !IsDotIdentifier(value))
            {
                throw this.Error($"DOT identifier '{value}' must be double-quoted.");
            }

            if (this.dot && !allowKeyword && IsDotKeyword(value))
            {
                throw this.Error($"Reserved DOT keyword '{value}' must be double-quoted when used as an identifier.");
            }

            return value;
        }

        /// <summary>Reads a plain quoted string with supported escapes.</summary>
        /// <param name="label">Whether to decode label-specific escapes.</param>
        /// <returns>The decoded string.</returns>
        internal string Quoted(bool label = true)
        {
            this.Expect("\"");
            StringBuilder value = new StringBuilder();
            while (!this.End && this.Current != '"')
            {
                char character = this.text[this.position++];
                if (character == '\\')
                {
                    if (this.End)
                    {
                        throw this.Error("Unterminated quoted string.");
                    }

                    char escaped = this.text[this.position++];
                    if (this.dot && !label && escaped != '"')
                    {
                        throw this.Error($"Unsupported escape '\\{escaped}' in a DOT identifier or non-label value. Use a plain quoted value.");
                    }

                    character = escaped switch
                    {
                        '\\' => '\\',
                        '"' => '"',
                        'n' => '\n',
                        'l' when this.dot => '\n',
                        'r' when this.dot => '\n',
                        _ => throw this.Error($"Unsupported string escape '\\{escaped}'."),
                    };
                }

                value.Append(character);
                if (value.Length > MaxTokenLength)
                {
                    throw this.Error($"Text-diagram labels and identifiers are limited to {MaxTokenLength} characters.");
                }
            }

            this.Expect("\"");
            return value.ToString();
        }

        /// <summary>Reads a Mermaid label and its closing delimiter.</summary>
        /// <param name="closing">The required closing delimiter.</param>
        /// <returns>The plain-text label.</returns>
        internal string Label(string closing)
        {
            this.SkipSpace();
            if (this.Current == '"')
            {
                string quoted = this.Quoted();
                if (quoted.StartsWith("`", StringComparison.Ordinal))
                {
                    throw this.Error("Unsupported Mermaid Markdown label. Use a plain quoted label.");
                }

                this.ValidateLabel(quoted);
                this.SkipSpace();
                this.Expect(closing);
                return quoted;
            }

            int start = this.position;
            while (!this.End && this.Current != '\n' && !this.At(closing))
            {
                this.position++;
            }

            string value = this.Token(start).Trim();
            this.ValidateLabel(value);
            this.Expect(closing);
            return value;
        }

        /// <summary>Creates a diagnostic naming the grammar and source location.</summary>
        /// <param name="message">The specific parse or mapping failure.</param>
        /// <returns>The import exception.</returns>
        internal InvalidDataException Error(string message)
        {
            int line = 1;
            int column = 1;
            for (int index = 0; index < this.position; index++)
            {
                if (this.text[index] == '\n')
                {
                    line++;
                    column = 1;
                }
                else
                {
                    column++;
                }
            }

            return new InvalidDataException($"{(this.dot ? "DOT" : "Mermaid")} line {line}, column {column}: {message}");
        }

        /// <summary>Describes the current token with bounded diagnostic output.</summary>
        /// <returns>The token excerpt or end-of-input description.</returns>
        internal string DescribeCurrent()
        {
            if (this.End)
            {
                return "end of input";
            }

            int end = this.position;
            while (end < this.text.Length && !char.IsWhiteSpace(this.text[end]) && end - this.position < 40)
            {
                end++;
            }

            return "'" + this.text.Substring(this.position, Math.Max(1, end - this.position)).Replace("\n", "\\n") + "'";
        }

        private static bool IsIdentifierCharacter(char value)
        {
            return char.IsLetterOrDigit(value) || value == '_' || value == '-' || value == '.';
        }

        private static bool IsDotKeyword(string value)
        {
            return value.ToLowerInvariant() is "node" or "edge" or "graph" or "digraph" or "subgraph" or "strict";
        }

        private static bool IsDotIdentifier(string value)
        {
            if (char.IsLetter(value[0]) || value[0] == '_')
            {
                foreach (char character in value)
                {
                    if (!char.IsLetterOrDigit(character) && character != '_')
                    {
                        return false;
                    }
                }

                return true;
            }

            bool digit = false;
            bool point = false;
            for (int index = value[0] == '-' ? 1 : 0; index < value.Length; index++)
            {
                if (value[index] >= '0' && value[index] <= '9')
                {
                    digit = true;
                }
                else if (value[index] == '.' && !point)
                {
                    point = true;
                }
                else
                {
                    return false;
                }
            }

            return digit;
        }

        private void ValidateLabel(string value)
        {
            for (int index = 0; index < value.Length; index++)
            {
                if (value[index] == '<' && index + 1 < value.Length && (char.IsLetter(value[index + 1]) || value[index + 1] == '/' || value[index + 1] == '!'))
                {
                    throw this.Error("Unsupported Mermaid HTML label. Use plain text.");
                }

                if (value[index] == '#' || value[index] == '&')
                {
                    int end = index + 1;
                    while (end < value.Length && (char.IsLetterOrDigit(value[end]) || value[end] == '#'))
                    {
                        end++;
                    }

                    if (end > index + 1 && end < value.Length && value[end] == ';')
                    {
                        throw this.Error("Unsupported Mermaid entity-encoded label. Use plain text.");
                    }

                    index = end - 1;
                }
            }
        }

        private string Token(int start)
        {
            if (this.position - start > MaxTokenLength)
            {
                throw this.Error($"Text-diagram labels and identifiers are limited to {MaxTokenLength} characters.");
            }

            return this.text.Substring(start, this.position - start);
        }
    }
}
