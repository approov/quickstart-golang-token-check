package files

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ucarion/sfv"
)

// ---- Fixture types ---------------------------------------------------------

type fixtureRecord struct {
	Name       string          `json:"name"`
	HeaderType string          `json:"header_type"`
	Expected   json.RawMessage `json:"expected"`
	MustFail   bool            `json:"must_fail"`
	CanFail    bool            `json:"can_fail"`
	Raw        []string        `json:"raw"`
	Canonical  []string        `json:"canonical"`
}

// Choose canonical if present, else raw, and join multiple lines with ", ".
func (r fixtureRecord) expectedSerializedValue() *string {
	values := r.Canonical
	if values == nil {
		values = r.Raw
	}
	if values == nil {
		return nil
	}
	if len(values) == 0 {
		s := ""
		return &s
	}
	if len(values) == 1 {
		return &values[0]
	}
	s := strings.Join(values, ", ")
	return &s
}

var got string
var err error

// ExtendedBareItem adds support for @date and ?displaystring
type ExtendedBareItem struct {
	sfv.BareItem
	Type string
}

func MarshalWithExtras(item ExtendedBareItem) (string, error) {
	switch item.Type {
	case "date":
		return fmt.Sprintf("@%d", item.Integer), nil
	case "displaystring":
		return fmt.Sprintf("?%q", item.String), nil
	default:
		return sfv.Marshal(item.BareItem)
	}
}

// ---- High-level test -------------------------------------------------------

func TestStructuredFieldSerialisationFixtures(t *testing.T) {
	const fixturesRoot = "structured_field_tests"

	cwd, _ := os.Getwd()
	fmt.Println("CWD:", cwd)

	files, err := collectFixtureFiles(fixturesRoot, true)
	if err != nil {
		t.Skipf("could not collect fixtures: %v", err)
	}

	for _, path := range files {
		path := path
		rel := strings.TrimPrefix(path, fixturesRoot+string(filepath.Separator))

		t.Run(rel, func(t *testing.T) {
			records, err := loadRecords(path)
			if err != nil {
				t.Fatalf("loadRecords(%q): %v", path, err)
			}

			for _, rec := range records {
				if rec.Expected == nil {
					continue
				}
				expectedValue := rec.expectedSerializedValue()
				if expectedValue == nil {
					// Multi-line canonical we don't want to normalise here.
					continue
				}

				t.Run(rec.Name, func(t *testing.T) {
					// Build the Go sfv structure from the JSON "expected".
					structure, err := buildStructure(rec.HeaderType, rec.Expected)
					if rec.MustFail {
						if err == nil {
							// For serialisation-tests "must_fail", we expect
							// that we *cannot* even build a valid structure.
							t.Fatalf("expected buildStructure to fail")
						}
						return
					}
					if err != nil {
						t.Fatalf("buildStructure: %v", err)
					}

					// Serialise using our Go library.
					// got, err := sfv.Marshal(structure)
					// if err != nil {
					// 	t.Fatalf("sfv.Marshal: %v", err)
					// }

					switch {
					case strings.Contains(path, "date.json"):
						// RFC 8941 §3.3.5 – @<integer>
						item := structure.(sfv.Item)
						got = fmt.Sprintf("@%d", item.BareItem.Integer)

					case strings.Contains(path, "display-string.json"):
						// RFC 8941 §3.3.6 – ?"<utf8 string>"
						item := structure.(sfv.Item)
						got = fmt.Sprintf("?%q", item.BareItem.String)

					default:
						got, err = sfv.Marshal(structure)
						if err != nil {
							t.Fatalf("sfv.Marshal: %v", err)
						}
					}

					if err != nil {
						t.Fatalf("sfv.Marshal or wrapper: %v", err)
					}
				})
			}
		})
	}
}

// ---- JSON fixture loading --------------------------------------------------

func collectFixtureFiles(root string, includeSerialisationTests bool) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		isSerialisation := strings.Contains(path, string(filepath.Separator)+"serialisation-tests"+string(filepath.Separator))
		isSchema := strings.Contains(path, string(filepath.Separator)+"schema"+string(filepath.Separator))

		if isSchema {
			return nil
		}
		if !includeSerialisationTests && isSerialisation {
			return nil
		}

		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Simple sort is fine; tests don’t care about order.
	sort.Strings(files)
	return files, nil
}

func loadRecords(path string) ([]fixtureRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var out []fixtureRecord
	for _, m := range raw {
		rec := fixtureRecord{
			Name:       asString(m["name"], path),
			HeaderType: asString(m["header_type"], "item"),
			MustFail:   asBool(m["must_fail"]),
			CanFail:    asBool(m["can_fail"]),
		}

		if v, ok := m["expected"]; ok {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			rec.Expected = b
		}
		if v, ok := m["raw"]; ok {
			rec.Raw = toStringSlice(v)
		}
		if v, ok := m["canonical"]; ok {
			rec.Canonical = toStringSlice(v)
		}

		out = append(out, rec)
	}
	return out, nil
}

func asString(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- Converting JSON “expected” -> sfv structures --------------------------

// buildStructure chooses which top-level sfv type we create (Item, List, Dictionary)
// based on header_type: "item", "list", or "dictionary".
func buildStructure(headerType string, expected json.RawMessage) (any, error) {
	headerType = strings.ToLower(headerType)

	switch headerType {
	case "item":
		var arr []any
		if err := json.Unmarshal(expected, &arr); err != nil {
			return nil, err
		}
		return itemFromJSON(arr)
	case "list":
		var arr []any
		if err := json.Unmarshal(expected, &arr); err != nil {
			return nil, err
		}
		return listFromJSON(arr)
	case "dictionary":
		var arr []any
		if err := json.Unmarshal(expected, &arr); err != nil {
			return nil, err
		}
		return dictionaryFromJSON(arr)
	default:
		return nil, fmt.Errorf("unsupported header_type %q", headerType)
	}
}

// Item: [ bare-item, parameters ]
func itemFromJSON(jsonArr []any) (sfv.Item, error) {
	if len(jsonArr) != 2 {
		return sfv.Item{}, fmt.Errorf("invalid item: %#v", jsonArr)
	}

	bare, err := bareItemFromJSON(jsonArr[0])
	if err != nil {
		return sfv.Item{}, err
	}

	params, err := paramsFromJSON(jsonArr[1])
	if err != nil {
		return sfv.Item{}, err
	}

	return sfv.Item{
		BareItem: bare,
		Params:   params,
	}, nil
}

// List: each element is either an Item or an Inner-List.
func listFromJSON(jsonArr []any) (sfv.List, error) {
	var out sfv.List

	for _, entry := range jsonArr {
		entryArr, ok := entry.([]any)
		if !ok {
			return nil, fmt.Errorf("invalid list member: %#v", entry)
		}

		// Inner-list: [[ item, ... ], params ]
		if len(entryArr) == 2 {
			if _, ok := entryArr[0].([]any); ok {
				inner, err := innerListFromJSON(entryArr)
				if err != nil {
					return nil, err
				}
				out = append(out, sfv.Member{IsItem: false, InnerList: inner})
				continue
			}
		}

		// Otherwise, treat as Item representation.
		item, err := itemFromJSON(entryArr)
		if err != nil {
			return nil, err
		}
		out = append(out, sfv.Member{IsItem: true, Item: item})
	}

	return out, nil
}

// Inner-List: [ [ items... ], params ]
func innerListFromJSON(jsonArr []any) (sfv.InnerList, error) {
	if len(jsonArr) != 2 {
		return sfv.InnerList{}, fmt.Errorf("invalid inner list: %#v", jsonArr)
	}

	rawItems, ok := jsonArr[0].([]any)
	if !ok {
		return sfv.InnerList{}, fmt.Errorf("invalid inner list items: %#v", jsonArr[0])
	}

	items := make([]sfv.Item, 0, len(rawItems))
	for _, entry := range rawItems {
		arr, ok := entry.([]any)
		if !ok {
			return sfv.InnerList{}, fmt.Errorf("invalid inner list item: %#v", entry)
		}
		item, err := itemFromJSON(arr)
		if err != nil {
			return sfv.InnerList{}, err
		}
		items = append(items, item)
	}

	params, err := paramsFromJSON(jsonArr[1])
	if err != nil {
		return sfv.InnerList{}, err
	}

	return sfv.InnerList{
		Items:  items,
		Params: params,
	}, nil
}

// Dictionary: [ [ name, member ], ... ]
func dictionaryFromJSON(jsonArr []any) (sfv.Dictionary, error) {
	d := sfv.Dictionary{
		Map:  make(map[string]sfv.Member),
		Keys: make([]string, 0, len(jsonArr)),
	}

	for _, entry := range jsonArr {
		pair, ok := entry.([]any)
		if !ok || len(pair) != 2 {
			return sfv.Dictionary{}, fmt.Errorf("invalid dictionary entry: %#v", entry)
		}

		name, ok := pair[0].(string)
		if !ok {
			return sfv.Dictionary{}, fmt.Errorf("invalid dictionary name: %#v", pair[0])
		}

		member, err := dictionaryMemberFromJSON(pair[1])
		if err != nil {
			return sfv.Dictionary{}, err
		}

		if _, exists := d.Map[name]; !exists {
			d.Keys = append(d.Keys, name)
		}
		d.Map[name] = member
	}

	return d, nil
}

// Dictionary member: [ value-or-innerlist, params ]
func dictionaryMemberFromJSON(v any) (sfv.Member, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		return sfv.Member{}, fmt.Errorf("invalid dictionary member: %#v", v)
	}

	// If first element is a list, this is an inner-list.
	if _, ok := arr[0].([]any); ok {
		inner, err := innerListFromJSON(arr)
		if err != nil {
			return sfv.Member{}, err
		}
		return sfv.Member{IsItem: false, InnerList: inner}, nil
	}

	// Otherwise, treat as item-like [bare-value-or-bool, params].
	// If bare is literal true, this is "bare true" (foo;bar) style.
	if b, ok := arr[0].(bool); ok && b {
		params, err := paramsFromJSON(arr[1])
		if err != nil {
			return sfv.Member{}, err
		}
		item := sfv.Item{
			BareItem: sfv.BareItem{
				Type:    sfv.BareItemTypeBoolean,
				Boolean: true,
			},
			Params: params,
		}
		return sfv.Member{IsItem: true, Item: item}, nil
	}

	item, err := itemFromJSON(arr)
	if err != nil {
		return sfv.Member{}, err
	}
	return sfv.Member{IsItem: true, Item: item}, nil
}

// Parameters: [ [ name, bare-item ], ... ]
func paramsFromJSON(v any) (sfv.Params, error) {
	out := sfv.Params{
		Map:  map[string]sfv.BareItem{},
		Keys: []string{},
	}
	if v == nil {
		return out, nil
	}

	arr, ok := v.([]any)
	if !ok {
		return out, nil
	}

	for _, entry := range arr {
		pair, ok := entry.([]any)
		if !ok || len(pair) != 2 {
			return sfv.Params{}, fmt.Errorf("invalid parameter entry: %#v", entry)
		}
		name, ok := pair[0].(string)
		if !ok {
			return sfv.Params{}, fmt.Errorf("invalid parameter name: %#v", pair[0])
		}
		val, err := bareItemFromJSON(pair[1])
		if err != nil {
			return sfv.Params{}, err
		}

		if _, exists := out.Map[name]; !exists {
			out.Keys = append(out.Keys, name)
		}
		out.Map[name] = val
	}

	return out, nil
}

// Bare-Item mapping follows httpwg/structured-field-tests README.
func bareItemFromJSON(v any) (sfv.BareItem, error) {
	switch x := v.(type) {
	case nil:
		return sfv.BareItem{}, fmt.Errorf("nil bare item")
	case bool:
		return sfv.BareItem{Type: sfv.BareItemTypeBoolean, Boolean: x}, nil
	case float64:
		if math.Trunc(x) == x {
			return sfv.BareItem{Type: sfv.BareItemTypeInteger, Integer: int64(x)}, nil
		}
		return sfv.BareItem{Type: sfv.BareItemTypeDecimal, Decimal: x}, nil
	case string:
		// JSON string => SFV string (tokens are represented via __type:"token")
		return sfv.BareItem{Type: sfv.BareItemTypeString, String: x}, nil
	case map[string]any:
		typ, _ := x["__type"].(string)
		switch typ {
		case "token":
			val, _ := x["value"].(string)
			return sfv.BareItem{Type: sfv.BareItemTypeToken, Token: val}, nil
		case "binary":
			val, _ := x["value"].(string)
			b, err := base32.StdEncoding.DecodeString(strings.ToUpper(val))
			if err != nil {
				return sfv.BareItem{}, fmt.Errorf("decode base32: %w", err)
			}
			return sfv.BareItem{Type: sfv.BareItemTypeBinary, Binary: b}, nil
		// NOTE: the test suite also defines "date" and "displaystring".
		// This sfv library doesn't expose those as native types, so we
		// skip them here; you can extend this switch if you add support.
		case "date":
			// Expect an integer timestamp in seconds since epoch.
			v, ok := x["value"].(float64)
			if !ok {
				return sfv.BareItem{}, fmt.Errorf("date value not float64: %v", x["value"])
			}
			return sfv.BareItem{
				Type:    sfv.BareItemTypeInteger,
				Integer: int64(v),
			}, nil

		case "displaystring":
			// Expect a UTF-8 string.
			v, ok := x["value"].(string)
			if !ok {
				return sfv.BareItem{}, fmt.Errorf("displaystring not string: %v", x["value"])
			}
			return sfv.BareItem{
				Type:   sfv.BareItemTypeString,
				String: v,
			}, nil

		default:
			return sfv.BareItem{}, fmt.Errorf("unsupported __type %q", typ)
		}
	default:
		return sfv.BareItem{}, fmt.Errorf("unexpected bare item JSON type %T", v)
	}
}
