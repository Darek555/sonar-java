/*
 * SonarQube Java
 * Copyright (C) 2012-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.java.api.semantic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.java.ast.JavaAstScanner;
import org.sonar.java.ast.visitors.SubscriptionVisitor;
import org.sonar.java.matcher.TypeCriteria;
import org.sonar.java.model.JParserTestUtils;
import org.sonar.java.model.JavaTree;
import org.sonar.java.model.VisitorsBridge;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.CompilationUnitTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodReferenceTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class MethodMatchersTest {

  @Test
  public void test_types() {
    String source = "" +
      /* 01 */ "interface A {\n" +
      /* 02 */ "  void f(int x);\n" +
      /* 03 */ "}\n" +
      /* 04 */ "interface B extends A {\n" +
      /* 05 */ "  void f(int x);\n" +
      /* 06 */ "}\n" +
      /* 07 */ "class X {\n" +
      /* 08 */ "  void f(int x);\n" +
      /* 09 */ "}\n" +
      /* 10 */ "class Main {\n" +
      /* 11 */ "  void main(A a, B b, X x) {\n" +
      /* 12 */ "    a.f(12);\n" +
      /* 13 */ "    b.f(12);\n" +
      /* 14 */ "    x.f(12);\n" +
      /* 15 */ "  }\n" +
      /* 16 */ "} \n";

    // exact types
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withAnyParameters()))
      .containsExactly(2, 12);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("B").name("f").withAnyParameters()))
      .containsExactly(5, 13);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("X").name("f").withAnyParameters()))
      .containsExactly(8, 14);

    // sub types
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("A").name("f").withAnyParameters()))
      .containsExactly(2, 5, 12, 13);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("B").name("f").withAnyParameters()))
      .containsExactly(5, 13);

    // any types
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofAnyType().name("f").withAnyParameters()))
      .containsExactly(2, 5, 8, 12, 13, 14);

    // several types
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofTypes("B", "X").name("f").withAnyParameters()))
      .containsExactly(5, 8, 13, 14);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubTypes("A", "X").name("f").withAnyParameters()))
      .containsExactly(2, 5, 8, 12, 13, 14);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("B").ofSubType("X").name("f").withAnyParameters()))
      .containsExactly(5, 8, 13, 14);
  }

  @Test
  public void test_names() {
    String source = "" +
      /* 01 */ "interface A {\n" +
      /* 02 */ "  void a(int x);\n" +
      /* 03 */ "  void aa(int x);\n" +
      /* 04 */ "  void b(int x);\n" +
      /* 05 */ "}\n" +
      /* 06 */ "class Main {\n" +
      /* 07 */ "  void main(A a) {\n" +
      /* 08 */ "    a.a(12);\n" +
      /* 09 */ "    a.aa(12);\n" +
      /* 10 */ "    a.b(12);\n" +
      /* 11 */ "    new Main();\n" +
      /* 12 */ "  }\n" +
      /* 13 */ "} \n";

    // one name
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("a").withAnyParameters()))
      .containsExactly(2, 8);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("aa").withAnyParameters()))
      .containsExactly(3, 9);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("b").withAnyParameters()))
      .containsExactly(4, 10);

    // several names
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").names("a", "b").withAnyParameters()))
      .containsExactly(2, 4, 8, 10);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("a").name("b").withAnyParameters()))
      .containsExactly(2, 4, 8, 10);

    // start with
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").startWithName("a").withAnyParameters()))
      .containsExactly(2, 3, 8, 9);

    // any names
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").anyName().withAnyParameters()))
      .containsExactly(2, 3, 4, 8, 9, 10);

    // predicate
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("B"::equalsIgnoreCase).withAnyParameters()))
      .containsExactly(4, 10);

    // constructor
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("Main").constructor().withAnyParameters()))
      .containsExactly(11);
  }

  @Test
  public void test_parameters() {
    String source = "" +
      /* 01 */ "interface A { \n" +
      /* 02 */ "  void f();\n" +
      /* 03 */ "  void f(int x);\n" +
      /* 04 */ "  void f(int x, long y);\n" +
      /* 05 */ "  void f(String x);\n" +
      /* 06 */ "  static void main(A a) {\n" +
      /* 07 */ "    a.f();\n" +
      /* 08 */ "    a.f(12);\n" +
      /* 09 */ "    a.f(12, 15L);\n" +
      /* 10 */ "    java.util.function.Consumer<Integer> c = a::f;\n" +
      /* 11 */ "  }\n" +
      /* 12 */ "} \n";

    // without parameters
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withoutParameters()))
      .containsExactly(2, 7);

    // with parameters
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withParameters("int")))
      .containsExactly(3, 8, 10);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withParameters("int", "long")))
      .containsExactly(4, 9);

    // several with parameters
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f")
      .withParameters("int")
      .withParameters("int", "long")))
      .containsExactly(3, 4, 8, 9, 10);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f")
      .withoutParameters()
      .withParameters("int")
      .withParameters("int", "long")))
      .containsExactly(2, 3, 4, 7, 8, 9, 10);

    // start with parameters
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f")
      .startWithParameters("int")))
      .containsExactly(3, 4, 8, 9, 10);

    // with any parameters
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withAnyParameters()))
      .containsExactly(2, 3, 4, 5, 7, 8, 9, 10);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withParameters(type -> true)))
      .containsExactly(2, 3, 4, 5, 7, 8, 9, 10);

    // predicate
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f")
      .withParameters(type -> type.is("int"), type -> !type.is("int"))))
      .containsExactly(4, 9);
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f")
      .startWithParameters(type -> type.is("int"))))
      .containsExactly(3, 4, 8, 9, 10);
  }

  @Test
  public void test_tree_and_symbol_and_or() {
    String source = "" +
      /* 01 */ "package pkg;\n" +
      /* 02 */ "import java.util.function.*;\n" +
      /* 03 */ "class A { \n" +
      /* 04 */ "  A(int x) { }\n" +
      /* 05 */ "  void f(int x) { }\n" +
      /* 06 */ "  void main() {\n" +
      /* 07 */ "    A a = new A(12);\n" +
      /* 08 */ "    a.f(12);\n" +
      /* 09 */ "    Consumer<Integer> c = a::f;\n" +
      /* 10 */ "    Supplier<A> s = A::new;\n" +
      /* 11 */ "  }\n" +
      /* 12 */ "} \n";

    // method f(int)
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.A").name("f").withParameters("int")))
      .containsExactly(5, 8, 9);
    assertThat(findMatchesOnSymbol(source, MethodMatchers.create().ofType("pkg.A").name("f").withParameters("int")))
      .containsExactly(5, 8); // missing 9 because symbol.isMethodSymbol() of method reference return false

    // constructor
    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.A").constructor().withParameters("int")))
      .containsExactly(4, 7); // missing 10 because "A::new" is an unknown type
    assertThat(findMatchesOnSymbol(source, MethodMatchers.create().ofType("pkg.A").constructor().withParameters("int")))
      .containsExactly(4, 7);

    // or
    assertThat(findMatchesOnTree(source, MethodMatchers.or(
      MethodMatchers.create().ofType("pkg.A").constructor().withParameters("int"),
      MethodMatchers.create().ofType("pkg.A").name("f").withParameters("int"))))
      .containsExactly(4, 5, 7, 8, 9);
    assertThat(findMatchesOnSymbol(source, MethodMatchers.or(
      MethodMatchers.create().ofType("pkg.A").constructor().withParameters("int"),
      MethodMatchers.create().ofType("pkg.A").name("f").withParameters("int"))))
      .containsExactly(4, 5, 7, 8);

    // empty
    assertThat(findMatchesOnTree(source, MethodMatchers.empty())).isEmpty();
    assertThat(findMatchesOnSymbol(source, MethodMatchers.empty())).isEmpty();
  }

  @Test
  public void test_inheritance() {
    String source = "" +
      /* 01 */ "package pkg;\n" +
      /* 02 */ "class A { }\n" +
      /* 03 */ "interface I {\n" +
      /* 04 */ "  void f();\n" +
      /* 05 */ "  void f(int x);\n" +
      /* 06 */ "}\n" +
      /* 07 */ "@FunctionalInterface\n" +
      /* 08 */ "interface J {\n" +
      /* 09 */ "  void f(int x);\n" +
      /* 10 */ "}\n" +
      /* 11 */ "abstract class B extends A implements I, J {\n" +
      /* 12 */ "  public void f() { }\n" +
      /* 13 */ "}\n" +
      /* 14 */ "class C extends B {\n" +
      /* 15 */ "  @Override\n" +
      /* 16 */ "  public void f(int x) { }\n" +
      /* 17 */ "}\n" +
      /* 18 */ "class D extends C {\n" +
      /* 19 */ "  @Override\n" +
      /* 20 */ "  public void f(int x) { }\n" +
      /* 21 */ "}\n" +
      /* 22 */ "class E extends D { }\n" +
      /* 23 */ "class F extends E { }\n" +
      /* 24 */ "class Main {\n" +
      /* 25 */ "  void main(Object o, A a, B b, C c, D d, E e, F f) {\n" +
      /* 26 */ "    o.toString();\n" +
      /* 27 */ "    a.toString();\n" +
      /* 28 */ "    b.f();\n" +
      /* 29 */ "    b.f(42);\n" +
      /* 30 */ "    c.f(42);\n" +
      /* 31 */ "    d.f(42);\n" +
      /* 32 */ "    e.f(42);\n" +
      /* 33 */ "    f.f(42);\n" +
      /* 34 */ "    f.f();\n" +
      /* 35 */ "    J j = d::f;\n" +
      /* 36 */ "    j = e::f;\n" +
      /* 37 */ "    j.f(42);\n" +
      /* 38 */ "  }\n" +
      /* 39 */ "}\n";

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("java.lang.Object").name("toString").withoutParameters()))
      .containsExactly(26);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("java.lang.Object").name("toString").withoutParameters()))
      .containsExactly(26, 27);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType(TypeCriteria.is("pkg.B")).name("f").withoutParameters()))
      .containsExactly(12, 28);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.B").name("f").withoutParameters()))
      .containsExactly(12, 28, 34);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.B").name("f").withParameters("int")))
      .containsExactly(16, 20, 29, 30, 31, 32, 33, 35, 36);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.F").name("f").withoutParameters()))
      .containsExactly(34);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.A").name("f").withParameters("int")))
      .isEmpty();

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.B").name("f").withParameters("int")))
      .containsExactly(29);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.C").name("f").withParameters("int")))
      .containsExactly(16, 30);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.D").name("f").withParameters("int")))
      .containsExactly(20, 31, 32, 33, 35, 36);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.D").name("f").withParameters("int")))
      .containsExactly(20, 31, 35);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.E").name("f").withParameters("int")))
      .containsExactly(32, 36);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("pkg.F").name("f").withParameters("int")))
      .containsExactly(33);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.A").name("f").withParameters("int")))
      .containsExactly(16, 20, 29, 30, 31, 32, 33, 35, 36);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.I").name("f").withParameters("int")))
      .containsExactly(5, 16, 20, 29, 30, 31, 32, 33, 35, 36);

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofSubType("pkg.J").name("f").withParameters("int")))
      .containsExactly(9, 16, 20, 29, 30, 31, 32, 33, 35, 36, 37);
  }

  @Test(expected = IllegalStateException.class)
  public void invalid_any_type() {
    MethodMatchers.create().ofType("A").ofAnyType().anyName().withAnyParameters();
  }

  @Test(expected = IllegalStateException.class)
  public void invalid_any_name() {
    MethodMatchers.create().ofAnyType().name("A").anyName().withAnyParameters();
  }

  @Test(expected = IllegalStateException.class)
  public void invalid_any_parameters() {
    MethodMatchers.create().ofAnyType().anyName().withParameters("int").withAnyParameters();
  }

  @Test(expected = IllegalStateException.class)
  public void invalid_matcher_without_type() {
    MethodTree methodTree = (MethodTree) firstMember("interface A { void f(); }");
    MethodMatchers matcher = MethodMatchers.create().name("f").withoutParameters();
    matcher.matches(methodTree);
  }

  @Test(expected = IllegalStateException.class)
  public void invalid_matcher_without_name() {
    MethodTree methodTree = (MethodTree) firstMember("interface A { void f(); }");
    MethodMatchers matcher = MethodMatchers.create().ofAnyType().withoutParameters();
    matcher.matches(methodTree);
  }

  @Test(expected = IllegalStateException.class)
  public void invalid_matcher_without_parameters() {
    MethodTree methodTree = (MethodTree) firstMember("interface A { void f(); }");
    MethodMatchers matcher = MethodMatchers.create().ofAnyType().anyName();
    matcher.matches(methodTree);
  }

  @Test
  public void test_method_selector_and_method_identifier() {
    String source = "" +
      /* 01 */ "class A {\n" +
      /* 02 */ "  void f(A a) {\n" +
      /* 03 */ "    f(this);\n" +
      /* 04 */ "    a.f(a);\n" +
      /* 05 */ "  }\n" +
      /* 06 */ "}\n";

    assertThat(findMatchesOnTree(source, MethodMatchers.create().ofType("A").name("f").withParameters("A")))
      .containsExactly(2, 3, 4);
  }

  public static Tree firstMember(String source) {
    CompilationUnitTree tree = JParserTestUtils.parse(source);
    ClassTree classTree = (ClassTree) tree.types().get(0);
    return classTree.members().get(0);
  }

  private static List<Integer> findMatchesOnTree(String fileContent, MethodMatchers matcher) {
    return findMatches(fileContent, matcher, false);
  }

  private static List<Integer> findMatchesOnSymbol(String fileContent, MethodMatchers matcher) {
    return findMatches(fileContent, matcher, true);
  }

  private static List<Integer> findMatches(String fileContent, MethodMatchers matcher, boolean useSymbol) {
    Visitor visitor = new Visitor(matcher, useSymbol);
    JavaAstScanner.scanSingleFileForTests(
      inputFile(fileContent),
      new VisitorsBridge(Collections.singletonList(visitor), new ArrayList<>(), null));
    return visitor.matches;
  }

  private static InputFile inputFile(String fileContent) {
    return new TestInputFileBuilder("", "TestFile.java")
      .setContents(fileContent)
      .setCharset(UTF_8)
      .setLanguage("java")
      .build();
  }

  private static class Visitor extends SubscriptionVisitor {

    public MethodMatchers matcher;
    private boolean useSymbol;
    public List<Integer> matches = new ArrayList<>();

    public Visitor(MethodMatchers matcher, boolean useSymbol) {
      this.matcher = matcher;
      this.useSymbol = useSymbol;
    }

    @Override
    public List<Tree.Kind> nodesToVisit() {
      return Arrays.asList(Tree.Kind.METHOD, Tree.Kind.CONSTRUCTOR, Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS, Tree.Kind.METHOD_REFERENCE);
    }

    @Override
    public void visitNode(Tree tree) {
      super.visitNode(tree);
      boolean match = false;
      if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
        if (useSymbol) {
          match = matcher.matches(((MethodInvocationTree) tree).symbol());
        } else {
          match = matcher.matches((MethodInvocationTree) tree);
        }
      } else if (tree.is(Tree.Kind.METHOD, Tree.Kind.CONSTRUCTOR)) {
        if (useSymbol) {
          match = matcher.matches(((MethodTree) tree).symbol());
        } else {
          match = matcher.matches((MethodTree) tree);
        }
      } else if (tree.is(Tree.Kind.NEW_CLASS)) {
        if (useSymbol) {
          match = matcher.matches(((NewClassTree) tree).constructorSymbol());
        } else {
          match = matcher.matches((NewClassTree) tree);
        }
      } else if (tree.is(Tree.Kind.METHOD_REFERENCE)) {
        if (useSymbol) {
          match = matcher.matches(((MethodReferenceTree) tree).symbolType().symbol());
        } else {
          match = matcher.matches((MethodReferenceTree) tree);
        }
      }
      if (match) {
        matches.add(((JavaTree) tree).getLine());
      }
    }
  }

}
