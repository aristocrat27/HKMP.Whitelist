using System;
using UnityEngine;
using UnityEngine.UI;

namespace HKMP.Whitelist.UI
{
    internal static class WhitelistUiFactory
    {
        private static Font _font;

        public static InputField CreateSearchField(
            GameObject parent,
            string placeholder,
            Action<string> changed)
        {
            GameObject root =
                new GameObject("WhitelistSearchField");

            root.transform.SetParent(
                parent.transform,
                false);

            RectTransform rootRect =
                root.AddComponent<RectTransform>();

            rootRect.anchorMin =
                new Vector2(0.05f, 0.2f);

            rootRect.anchorMax =
                new Vector2(0.95f, 0.8f);

            rootRect.offsetMin =
                Vector2.zero;

            rootRect.offsetMax =
                Vector2.zero;

            Image background =
                root.AddComponent<Image>();

            background.color =
                new Color(
                    0.08f,
                    0.08f,
                    0.08f,
                    0.95f);

            InputField input =
                root.AddComponent<InputField>();

            input.lineType =
                InputField.LineType.SingleLine;

            input.characterLimit =
                256;

            GameObject textObject =
                new GameObject("Text");

            textObject.transform.SetParent(
                root.transform,
                false);

            RectTransform textRect =
                textObject.AddComponent<RectTransform>();

            textRect.anchorMin =
                Vector2.zero;

            textRect.anchorMax =
                Vector2.one;

            textRect.offsetMin =
                new Vector2(18f, 0f);

            textRect.offsetMax =
                new Vector2(-18f, 0f);

            Text text =
                textObject.AddComponent<Text>();

            text.font =
                GetFont();

            text.fontSize =
                WhitelistUiStyle.Body;

            text.color =
                Color.white;

            text.alignment =
                TextAnchor.MiddleLeft;

            text.supportRichText =
                false;

            GameObject placeholderObject =
                new GameObject("Placeholder");

            placeholderObject.transform.SetParent(
                root.transform,
                false);

            RectTransform placeholderRect =
                placeholderObject.AddComponent<RectTransform>();

            placeholderRect.anchorMin =
                Vector2.zero;

            placeholderRect.anchorMax =
                Vector2.one;

            placeholderRect.offsetMin =
                new Vector2(18f, 0f);

            placeholderRect.offsetMax =
                new Vector2(-18f, 0f);

            Text placeholderText =
                placeholderObject.AddComponent<Text>();

            placeholderText.font =
                GetFont();

            placeholderText.fontSize =
                WhitelistUiStyle.Body;

            placeholderText.color =
                new Color(
                    1f,
                    1f,
                    1f,
                    0.45f);

            placeholderText.alignment =
                TextAnchor.MiddleLeft;

            placeholderText.text =
                placeholder ?? "";

            placeholderText.supportRichText =
                false;

            input.textComponent =
                text;

            input.placeholder =
                placeholderText;

            if (changed != null)
            {
                input.onValueChanged.AddListener(
                    value => changed(value));
            }

            return input;
        }

        private static Font GetFont()
        {
            if (_font != null)
            {
                return _font;
            }

            Font[] fonts =
                Resources.FindObjectsOfTypeAll<Font>();

            foreach (Font font in fonts)
            {
                if (font == null)
                {
                    continue;
                }

                string name =
                    font.name ?? "";

                if (name.IndexOf(
                        "perpetua",
                        StringComparison.OrdinalIgnoreCase) >= 0 ||
                    name.IndexOf(
                        "trajan",
                        StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    _font = font;
                    return _font;
                }
            }

            _font =
                Resources.GetBuiltinResource<Font>(
                    "Arial.ttf");

            return _font;
        }
    }
}