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

import com.google.common.annotations.Beta;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import org.sonar.java.matcher.EmptyMethodMatchers;
import org.sonar.java.matcher.MethodMatchersBuilder;
import org.sonar.java.matcher.MethodMatchersList;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodReferenceTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;

/**
 * <pre>
 * Immutable helper interface to help to identify method with given Type, Name and Parameter lists.
 *
 * The starting point to define a MethodMatchers is {@link #create()}.
 * It is required to provide at least one of the following:
 *
 * - a type definition, 1 or more call to:
 *   - ofSubType(String fullyQualifiedTypeName)
 *   - ofSubTypes(String... fullyQualifiedTypeNames)
 *   - ofType(String fullyQualifiedTypeName)
 *   - ofTypes(String... fullyQualifiedTypeNames)
 *   - ofType(Predicate<Type> typePredicate)
 *   - ofAnyType()                  // same as ofType(type -> true)
 *
 * - a method name, 1 or more call to:
 *   - name(String methodName)
 *   - names(String... names)
 *   - startWithName(String name)
 *   - constructor()
 *   - name(Predicate<String> namePredicate)
 *   - anyName()                    // same as name(name -> true)
 *
 * - a list of parameters, 1 or more call to:
 *   - withoutParameters()
 *   - withParameters(String... parametersType)
 *   - withParameters(Predicate<Type>... parametersType)
 *   - withParameters(Predicate<List<Type>> parametersType)
 *   - startWithParameters(String... parametersType)
 *   - startWithParameters(Predicate<Type>... parametersType)
 *   - withAnyParameters()          // same as withParameters((List<Type> parameters) -> true)
 *
 * If any of the three is missing, the matcher throws an Exception.
 * The matcher will return true only when the three predicates are respected.
 * It is also possible to define a name/type/parameters multiple times, to match one method OR another.
 *
 * Examples:
 *
 * - match method "a" and "b" from any type, and without parameters
 *     MethodMatchers.create().ofAnyType().names("a", "b").withoutParameters();
 *   alternatively
 *     MethodMatchers.create().ofAnyType().name("a").name("b").withoutParameters();
 *
 * - match method "a" and "b" from (subtype) of A, and "b" and "c" from B, with any parameters:
 *     MethodMatchers.or(
 *       MethodMatchers.create().ofSubType("A").names("a", "b").withAnyParameters(),
 *       MethodMatchers.create().ofSubType("B").names("b", "c").withAnyParameters());
 *
 * - match method "f" with any type and with:
 *     MethodMatchers.create().ofAnyType().name("f")
 *     - one parameter of type either int or long
 *        .withParameters("int").withParameters("long");
 *     - one parameter of type int or one parameter of type long with any other number of parameters
 *        .withParameters("int").startWithParameters("long");
 *
 * - match any method with any type, with parameter int, any, int
 *     MethodMatchers.create().ofAnyType().anyName().withParameters(t-> t.is("int"), t -> true, t -> t.is("int"));
 *
 * - match any type AND method name "a" OR "b" AND parameter int OR long
 *     MethodMatchers.create().ofAnyType().name("a").name("b").withParameters("int").withParameters("long")
 * </pre>
 */
@Beta
public interface MethodMatchers {

  boolean matches(NewClassTree newClassTree);
  boolean matches(MethodInvocationTree mit);
  boolean matches(MethodTree methodTree);
  boolean matches(MethodReferenceTree methodReferenceTree);
  boolean matches(Symbol symbol);

  static MethodMatchers.Builder create() {
    return new MethodMatchersBuilder();
  }

  // Methods related to combination

  /**
   * Combine multiple method matcher. The matcher will match any of the given matcher.
   */
  static MethodMatchers or(MethodMatchers... matchers) {
    return or(Arrays.asList(matchers));
  }

  static MethodMatchers or(List<? extends MethodMatchers> matchers) {
    return new MethodMatchersList(matchers);
  }

  static MethodMatchers empty() {
    return EmptyMethodMatchers.getInstance();
  }

  interface Builder extends MethodMatchers {

    // Methods related to types

    /**
     * Match the type and sub-type of the fully qualified name.
     */
    MethodMatchers.Builder ofSubType(String fullyQualifiedTypeName);

    /**
     * Match any of the type and sub-type of the fully qualified names.
     */
    MethodMatchers.Builder ofSubTypes(String... fullyQualifiedTypeNames);

    /**
     * Match any type.
     */
    MethodMatchers.Builder ofAnyType();

    /**
     * Match the fully qualified name type, but not the subtype.
     */
    MethodMatchers.Builder ofType(String fullyQualifiedTypeName);

    /**
     * Match any of the fully qualified name types, but not the subtype.
     */
    MethodMatchers.Builder ofTypes(String... fullyQualifiedTypeNames);

    /**
     * Match a type matching a predicate.
     */
    MethodMatchers.Builder ofType(Predicate<Type> typePredicate);

    // Methods related to name

    /**
     * Set a method name to match.
     * Can be called multiple times to match any of the name.
     */
    MethodMatchers.Builder name(String methodName);

    /**
     * Match a method with any name is the list.
     */
    MethodMatchers.Builder names(String... names);

    /**
     * Match a method with any name.
     * Equivalent to .name(n -> true).
     */
    MethodMatchers.Builder anyName();

    /**
     * Match a name starting with a prefix.
     * Equivalent to .name(n -> n.startWith("something"))
     */
    MethodMatchers.Builder startWithName(String name);

    /**
     * Match a constructor.
     * Equivalent to .name(n -> "<init>".equals(n))
     */
    MethodMatchers.Builder constructor();

    /**
     * Match the name matching the predicate.
     * Can be called multiple times to match a method satisfying a predicate or another.
     */
    MethodMatchers.Builder name(Predicate<String> namePredicate);

    // Methods related to parameters
    /**
     * Exact method signature.
     * Can be called multiple time to match any of the method signatures.
     */
    MethodMatchers.Builder withoutParameters();
    MethodMatchers.Builder withParameters(String... parametersType);
    MethodMatchers.Builder withParameters(Predicate<Type>... parametersType);
    MethodMatchers.Builder withParameters(Predicate<List<Type>> parametersType);
    MethodMatchers.Builder withAnyParameters();

    /**
     * Start of a parameter signature, with any other (0 or more) parameter of any type.
     * Can be called multiple time to match any of the method signatures.
     */
    MethodMatchers.Builder startWithParameters(String... parametersType);
    MethodMatchers.Builder startWithParameters(Predicate<Type>... parametersType);

  }

}
