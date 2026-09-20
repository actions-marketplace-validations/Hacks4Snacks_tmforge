namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using ThreatModelForge.Model;

    /// <summary>
    /// Resolves <see cref="IThreatModelFormat"/> providers by identifier, file extension, or
    /// content sniffing, and is the single entry point consumers use to load and save threat
    /// models instead of calling <see cref="ThreatModel"/> serialization directly.
    /// </summary>
    public sealed class ThreatModelFormatRegistry
    {
        private readonly List<IThreatModelFormat> formats;

        /// <summary>
        /// Initializes a new instance of the <see cref="ThreatModelFormatRegistry"/> class.
        /// </summary>
        /// <param name="formats">The format providers to register, in priority order.</param>
        public ThreatModelFormatRegistry(IEnumerable<IThreatModelFormat> formats)
        {
            if (formats == null)
            {
                throw new ArgumentNullException(nameof(formats));
            }

            this.formats = new List<IThreatModelFormat>(formats);
        }

        /// <summary>
        /// Gets the registered format providers, in priority order.
        /// </summary>
        public IReadOnlyList<IThreatModelFormat> Formats => this.formats;

        /// <summary>
        /// Creates a registry containing the built-in format providers.
        /// </summary>
        /// <returns>A registry with the default providers registered.</returns>
        public static ThreatModelFormatRegistry CreateDefault()
        {
            return new ThreatModelFormatRegistry(new IThreatModelFormat[] { new Tm7Format(), new TmForgeJsonFormat(), new DrawIoFormat(), new VisioFormat(), new ThreatDragonFormat(), new MermaidFormat(), new GraphvizDotFormat() });
        }

        /// <summary>
        /// Finds a provider by its stable identifier.
        /// </summary>
        /// <param name="id">The format identifier (case-insensitive).</param>
        /// <returns>The matching provider, or <see langword="null"/> if none is registered.</returns>
        public IThreatModelFormat? FindById(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(id));
            }

            return this.formats.FirstOrDefault(format => string.Equals(format.Id, id, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Finds a provider by file extension or path.
        /// </summary>
        /// <param name="pathOrExtension">A file path or extension (for example, <c>.tm7</c>).</param>
        /// <returns>The matching provider, or <see langword="null"/> if none is registered.</returns>
        public IThreatModelFormat? FindByExtension(string pathOrExtension)
        {
            if (string.IsNullOrEmpty(pathOrExtension))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(pathOrExtension));
            }

            string extension = Path.GetExtension(pathOrExtension);
            if (string.IsNullOrEmpty(extension))
            {
                extension = pathOrExtension.StartsWith(".", StringComparison.Ordinal)
                    ? pathOrExtension
                    : "." + pathOrExtension;
            }

            foreach (IThreatModelFormat format in this.formats)
            {
                foreach (string candidate in format.Extensions.Where(candidate => string.Equals(candidate, extension, StringComparison.OrdinalIgnoreCase)))
                {
                    return format;
                }
            }

            return null;
        }

        /// <summary>
        /// Finds the first readable provider whose content sniff matches the supplied stream.
        /// The stream position is left unchanged.
        /// </summary>
        /// <param name="stream">The seekable stream to inspect.</param>
        /// <returns>The matching provider, or <see langword="null"/> if none matches.</returns>
        public IThreatModelFormat? Sniff(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            return this.formats.FirstOrDefault(format => format.Capabilities.CanRead && format.CanRead(stream));
        }

        /// <summary>
        /// Resolves the provider to use when writing to the supplied path.
        /// </summary>
        /// <param name="path">The destination file path.</param>
        /// <param name="formatId">An optional explicit format identifier.</param>
        /// <returns>The provider to use for writing.</returns>
        public IThreatModelFormat ResolveForWrite(string path, string? formatId = null)
        {
            IThreatModelFormat format = this.ResolveByIdOrExtension(path, formatId);
            if (!format.Capabilities.CanWrite)
            {
                throw new NotSupportedException($"Format '{format.Id}' does not support writing.");
            }

            return format;
        }

        /// <summary>
        /// Loads a threat model from a file, resolving the format by explicit identifier, then
        /// by file extension, then by content sniffing.
        /// </summary>
        /// <param name="path">The source file path.</param>
        /// <param name="formatId">An optional explicit format identifier.</param>
        /// <returns>The loaded <see cref="ThreatModel"/>.</returns>
        public ThreatModel Load(string path, string? formatId = null)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(path));
            }

            using (FileStream stream = File.OpenRead(path))
            {
                IThreatModelFormat? format = !string.IsNullOrEmpty(formatId)
                    ? this.FindById(formatId!) ?? throw new NotSupportedException($"No threat model format with id '{formatId}'.")
                    : this.FindByExtension(path);

                if (format == null || !format.Capabilities.CanRead)
                {
                    format = this.Sniff(stream)
                        ?? throw new NotSupportedException(
                            $"Could not determine a readable threat model format for '{path}'. Specify a format id.");
                }

                return format.Read(stream);
            }
        }

        /// <summary>
        /// Loads a threat model from a stream, resolving the format by explicit identifier or by
        /// content sniffing.
        /// </summary>
        /// <param name="stream">The seekable source stream.</param>
        /// <param name="formatId">An optional explicit format identifier.</param>
        /// <returns>The loaded <see cref="ThreatModel"/>.</returns>
        public ThreatModel Load(Stream stream, string? formatId = null)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            IThreatModelFormat format = !string.IsNullOrEmpty(formatId)
                ? this.FindById(formatId!) ?? throw new NotSupportedException($"No threat model format with id '{formatId}'.")
                : this.Sniff(stream)
                    ?? throw new NotSupportedException(
                        "Could not determine a readable threat model format from the stream content. Specify a format id.");

            return format.Read(stream);
        }

        /// <summary>
        /// Saves a threat model to a file, resolving the format by explicit identifier or by file
        /// extension.
        /// </summary>
        /// <param name="model">The model to save.</param>
        /// <param name="path">The destination file path.</param>
        /// <param name="formatId">An optional explicit format identifier.</param>
        public void Save(ThreatModel model, string path, string? formatId = null)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            IThreatModelFormat format = this.ResolveForWrite(path, formatId);
            using (FileStream stream = File.Create(path))
            {
                format.Write(model, stream);
            }
        }

        private IThreatModelFormat ResolveByIdOrExtension(string path, string? formatId)
        {
            if (!string.IsNullOrEmpty(formatId))
            {
                return this.FindById(formatId!)
                    ?? throw new NotSupportedException($"No threat model format with id '{formatId}'.");
            }

            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(path));
            }

            return this.FindByExtension(path)
                ?? throw new NotSupportedException(
                    $"No threat model format is registered for '{path}'. Specify a format id.");
        }
    }
}
