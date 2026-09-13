namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Implements <c>tmforge layout</c>: applies a deterministic, dependency-free layered auto-layout
    /// to a model's pages, so an author never has to hand-place coordinates. Components are arranged
    /// left-to-right by their data flows inside the trust boundary they already belong to, boundaries
    /// are resized around their members, and flow labels are placed clear of the shapes and of each
    /// other. <c>--labels</c> restricts it to the labels, which is what a model with hand-placed or
    /// manifest-declared geometry wants.
    /// </summary>
    internal static class LayoutCommand
    {
        /// <summary>
        /// Runs the layout command.
        /// </summary>
        /// <param name="args">The command arguments (after the verb).</param>
        /// <returns>Zero on success; a non-zero value on error.</returns>
        public static int Run(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            CliArgs parsed = CliArgs.Parse(args, new[] { "node-spacing", "layer-spacing", "page" }, new[] { "labels", "check" });
            if (parsed.Help)
            {
                PrintUsage();
                return 0;
            }

            bool labelsOnly = parsed.HasFlag("labels");
            bool check = parsed.HasFlag("check");
            if (parsed.UnknownFlags.Count > 0)
            {
                Console.Error.WriteLine("Unknown option: " + parsed.UnknownFlags[0]);
                PrintUsage();
                return 1;
            }

            string? input = parsed.Positionals.Count > 0 ? parsed.Positionals[0] : null;
            if (string.IsNullOrEmpty(input))
            {
                PrintUsage();
                return 1;
            }

            if (!File.Exists(input))
            {
                Console.Error.WriteLine("File not found: " + input);
                return 1;
            }

            (ThreatModel model, IThreatModelFormat? format) = CliModelLoader.Load(input!);
            if (format == null || (!check && !format.Capabilities.CanWrite))
            {
                Console.Error.WriteLine("The model's format does not support writing.");
                return 1;
            }

            LayoutOptions options = new LayoutOptions();
            if (TryGetInt(parsed, "node-spacing", out int nodeSpacing))
            {
                options.NodeSpacing = nodeSpacing;
            }

            if (TryGetInt(parsed, "layer-spacing", out int layerSpacing))
            {
                options.LayerSpacing = layerSpacing;
            }

            string? pageSpec = parsed.Get("page");
            List<DrawingSurfaceModel> targets = new List<DrawingSurfaceModel>();
            if (string.IsNullOrEmpty(pageSpec))
            {
                targets.AddRange(model.DrawingSurfaceList);
            }
            else if (AuthoringSupport.TryResolveDiagram(model, pageSpec!, out DrawingSurfaceModel? resolved, out string? pageError))
            {
                targets.Add(resolved!);
            }
            else
            {
                Console.Error.WriteLine(pageError);
                return 1;
            }

            int components = 0;
            int labelled = 0;
            List<LabelOverlap> overlaps = new List<LabelOverlap>();
            foreach (DrawingSurfaceModel diagram in targets)
            {
                components += diagram.Borders.Values.OfType<DrawingElement>().Count(element => !(element is BorderBoundary));
                if (check)
                {
                    overlaps.AddRange(DiagramLabels.Inspect(diagram, options));
                    continue;
                }

                if (labelsOnly)
                {
                    labelled += DiagramLabels.Deconflict(diagram, options);
                }
                else
                {
                    labelled += DiagramLayout.Apply(diagram, options);
                }

                overlaps.AddRange(DiagramLabels.Inspect(diagram, options));
            }

            if (check)
            {
                return Report(parsed, targets.Count, components, overlaps);
            }

            AuthoringSupport.Save(model, input!, format);

            if (parsed.Json)
            {
                CliJson.WriteEnvelope("layout", new
                {
                    pages = targets.Count,
                    components,
                    labelsMoved = labelled,
                    labelOverlaps = overlaps.Count,
                });
            }
            else
            {
                Console.Error.WriteLine((labelsOnly
                    ? "Placed " + labelled + " flow label(s)"
                    : "Laid out " + components + " component(s)") +
                    " across " + targets.Count + " page(s) in " + input + ".");
                WarnAboutOverlaps(overlaps);
            }

            return 0;
        }

        /// <summary>
        /// Reports the label collisions found by <c>--check</c> without writing the model, and fails
        /// when any remain so a publishing gate can depend on the diagram being legible.
        /// </summary>
        /// <param name="parsed">The parsed arguments.</param>
        /// <param name="pages">The number of pages inspected.</param>
        /// <param name="components">The number of components inspected.</param>
        /// <param name="overlaps">The collisions found.</param>
        /// <returns>Zero when the diagram is legible; one when it is not.</returns>
        private static int Report(CliArgs parsed, int pages, int components, List<LabelOverlap> overlaps)
        {
            if (parsed.Json)
            {
                CliJson.WriteEnvelope("layout", new
                {
                    pages,
                    components,
                    labelOverlaps = overlaps.Count,
                    overlaps = overlaps.Select(overlap => new
                    {
                        flow = overlap.Flow,
                        obstructedBy = overlap.ObstructedBy,
                        kind = overlap.Kind,
                        area = overlap.Area,
                    }).ToList(),
                });
            }
            else if (overlaps.Count == 0)
            {
                Console.Error.WriteLine("No obstructed flow labels across " + pages + " page(s).");
            }
            else
            {
                WarnAboutOverlaps(overlaps);
                foreach (LabelOverlap overlap in overlaps)
                {
                    Console.Error.WriteLine("  '" + overlap.Flow + "' is covered by the " + overlap.Kind + " '" + overlap.ObstructedBy + "'.");
                }
            }

            return overlaps.Count == 0 ? 0 : 1;
        }

        /// <summary>
        /// Warns that labels remain obstructed. Layout can move a label but not shorten it: a flow
        /// name wider than the space between the elements it joins cannot be placed clear of them, so
        /// the remedy is a shorter name (with the sentence moved into a property) or fewer objects per
        /// page, and the caller is the only one who can choose.
        /// </summary>
        /// <param name="overlaps">The collisions found.</param>
        private static void WarnAboutOverlaps(List<LabelOverlap> overlaps)
        {
            if (overlaps.Count == 0)
            {
                return;
            }

            Console.Error.WriteLine(
                overlaps.Count + " flow label(s) are still covered. Flow names are drawn unwrapped, so a long " +
                "name needs more room than the flow it names; shorten the names or split the page.");
        }

        private static bool TryGetInt(CliArgs parsed, string name, out int value)
        {
            string? raw = parsed.Get(name);
            if (!string.IsNullOrEmpty(raw) && int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            {
                return true;
            }

            value = 0;
            return false;
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Auto-lay-out a model's pages (layered, trust-boundary aware, with flow labels placed).");
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  tmforge layout [--page <name|index>] [--node-spacing <n>] [--layer-spacing <n>] [--labels] [--check] [--json] <model>");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Arranges components by their data flows so you need not hand-place coordinates.");
            Console.Error.WriteLine("Components keep the trust boundary they were in; boundaries are resized around them.");
            Console.Error.WriteLine("  --labels  Place only the flow labels, leaving hand-placed shapes exactly where they are.");
            Console.Error.WriteLine("  --check   Report obstructed flow labels without writing; exits 1 when any remain.");
        }
    }
}
