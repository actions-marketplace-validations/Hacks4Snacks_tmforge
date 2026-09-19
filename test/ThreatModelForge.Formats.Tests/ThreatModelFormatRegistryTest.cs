namespace ThreatModelForge.Formats.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Model;

    /// <summary>
    /// Unit tests for <see cref="ThreatModelFormatRegistry"/>.
    /// </summary>
    [TestClass]
    public class ThreatModelFormatRegistryTest
    {
        /// <summary>
        /// Gets or sets the test context, used to locate deployed fixtures.
        /// </summary>
        public TestContext? TestContext { get; set; }

        /// <summary>
        /// Verifies that the default registry contains the built-in <c>.tm7</c>,
        /// <c>tmforge-json</c>, <c>.drawio</c>, <c>.vsdx</c>, and Threat Dragon providers.
        /// </summary>
        [TestMethod]
        public void CreateDefaultContainsBuiltinFormats()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            Assert.AreEqual(5, registry.Formats.Count);
            Assert.IsTrue(registry.Formats.Any(f => f is Tm7Format));
            Assert.IsTrue(registry.Formats.Any(f => f is TmForgeJsonFormat));
            Assert.IsTrue(registry.Formats.Any(f => f is DrawIoFormat));
            Assert.IsTrue(registry.Formats.Any(f => f is VisioFormat));
            Assert.IsTrue(registry.Formats.Any(f => f is ThreatDragonFormat));
        }

        /// <summary>
        /// Verifies that <see cref="ThreatModelFormatRegistry.FindById(string)"/> is
        /// case-insensitive and returns <see langword="null"/> for unknown identifiers.
        /// </summary>
        [TestMethod]
        public void FindByIdIsCaseInsensitive()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            Assert.IsNotNull(registry.FindById("tm7"));
            Assert.IsNotNull(registry.FindById("TM7"));
            Assert.IsNull(registry.FindById("does-not-exist"));
        }

        /// <summary>
        /// Verifies that <see cref="ThreatModelFormatRegistry.FindByExtension(string)"/> resolves
        /// paths, dotted extensions, and bare extensions.
        /// </summary>
        [TestMethod]
        public void FindByExtensionResolvesVariants()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            Assert.IsNotNull(registry.FindByExtension("/tmp/model.tm7"));
            Assert.IsNotNull(registry.FindByExtension(".tm7"));
            Assert.IsNotNull(registry.FindByExtension("tm7"));
            Assert.IsNull(registry.FindByExtension("model.json"));
        }

        /// <summary>
        /// Verifies that <see cref="ThreatModelFormatRegistry.Sniff(Stream)"/> matches
        /// <c>.tm7</c> content and returns <see langword="null"/> otherwise.
        /// </summary>
        [TestMethod]
        public void SniffMatchesTm7ContentOnly()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            using (MemoryStream tm7 = WriteEmptyModel())
            {
                Assert.IsNotNull(registry.Sniff(tm7));
            }

            using (MemoryStream other = new MemoryStream(Encoding.UTF8.GetBytes("{\"format\":\"other\"}")))
            {
                Assert.IsNull(registry.Sniff(other));
            }
        }

        /// <summary>
        /// Verifies that loading from a stream without a format id succeeds by content sniffing.
        /// </summary>
        [TestMethod]
        public void LoadFromStreamSniffsFormat()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            using (MemoryStream tm7 = WriteEmptyModel())
            {
                ThreatModel model = registry.Load(tm7);
                Assert.IsNotNull(model);
            }
        }

        /// <summary>
        /// Verifies that loading unrecognized stream content throws.
        /// </summary>
        [TestMethod]
        public void LoadFromStreamUnknownContentThrows()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            using (MemoryStream other = new MemoryStream(Encoding.UTF8.GetBytes("nope")))
            {
                Assert.Throws<NotSupportedException>(() => registry.Load(other));
            }
        }

        /// <summary>
        /// Verifies that loading from a real <c>.tm7</c> path resolves by extension.
        /// </summary>
        [TestMethod]
        public void LoadFromPathResolvesByExtension()
        {
            Assert.IsNotNull(this.TestContext!.DeploymentDirectory);
            string sourcePath = Path.Join(this.TestContext!.DeploymentDirectory!, "SampleModel.tm7");
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            ThreatModel model = registry.Load(sourcePath);

            Assert.IsNotNull(model);
            Assert.IsTrue(model.DrawingSurfaceList.Count > 0);
        }

        /// <summary>
        /// Verifies that saving through the registry resolves the provider by extension and that
        /// the written file can be loaded back.
        /// </summary>
        [TestMethod]
        public void SaveResolvesByExtensionAndRoundTrips()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();
            string path = Path.Join(Path.GetTempPath(), $"{Guid.NewGuid()}.tm7");

            try
            {
                registry.Save(new ThreatModel(), path);
                ThreatModel reloaded = registry.Load(path);
                Assert.IsNotNull(reloaded);
            }
            finally
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }

        /// <summary>
        /// Verifies that resolving a writer for an unknown extension without a format id throws.
        /// </summary>
        [TestMethod]
        public void ResolveForWriteUnknownExtensionThrows()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            Assert.Throws<NotSupportedException>(() => registry.ResolveForWrite("model.unknown"));
        }

        private static MemoryStream WriteEmptyModel()
        {
            MemoryStream stream = new MemoryStream();
            new Tm7Format().Write(new ThreatModel(), stream);
            stream.Position = 0;
            return stream;
        }
    }
}
