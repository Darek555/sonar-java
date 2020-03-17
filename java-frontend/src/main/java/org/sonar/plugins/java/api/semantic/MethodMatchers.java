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

import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import org.sonar.java.matcher.MethodMatchersBuilder;
import org.sonar.java.matcher.MethodMatchersList;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodReferenceTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;

/**
 * Helper interface to help to identify method with given Type, Name and Parameter lists.
 *
 * The starting point to define a MethodMatcher is {@link #create()}.
 * It is required to provide at least the following:
 *
 * - a type definition
 * - a method name
 * - a list of parameters
 *
 * If any of the three is missing, throw an Exception.
 * For any of the three elements above, you can specify that any name/type is accepted by using the predicate name -> true.
 * It is also possible to define a name/type multiple times, to emmatch one method OR another.
 *
 * Examples:
 *
 * - match method "a" and "b" from any type, and without parameters
 * MethodMatcher.create().ofAnyType().names("a", "b").withParameters();
 * alternatively
 * MethodMatcher.create().ofAnyType().name("a").name("b").withParameters();
 *
 * - match method "a" and "b" from (subtype) of A, and "b" and "c" from B, with any parameters:
 * MethodMatcher.create().ofSubType("A").names("a", "b").startWithParameters().or(
 * MethodMatcher.create().ofSubType("B").names("b", "c").startWithParameters());
 *
 * - match method "f" with any type and with:
 *   MethodMatcher.create().ofAnyType().name("f")
 *  - one parameter of type either int or long
 *    .withParameters("int").withParameters("long");
 *  - one parameter of type int or one parameter of type long with any other number of parameters
 *    .withParameters("int").startWithParameters("long");
 *
 * - match any method with any type, with parameter int, any, int
 *   MethodMatcher.create().anyName().withParameters(t-> t.is("int"), t -> true, t -> t.is("int"));
 *
 * TODO: add more example
 *
 */
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
    return new MethodMatchersList(Arrays.asList(matchers));
  }

  static MethodMatchers or(List<MethodMatchers> matchers) {
    return new MethodMatchersList(matchers);
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
     * Exact list of parameters.
     * Can be called multiple time to match any of the parameters lists.
     */
    MethodMatchers.Builder withoutParameters();
    MethodMatchers.Builder withParameters(String... parametersType);
    MethodMatchers.Builder withParameters(Predicate<Type>... parametersType);
    MethodMatchers.Builder withParameters(Predicate<List<Type>> parametersType);
    MethodMatchers.Builder withAnyParameters();

    /**
     * Start of list of parameters, with any other (0 or more) parameter of any type.
     * Can be called multiple time to match any of the parameters lists.
     */
    MethodMatchers.Builder startWithParameters(String... parametersType);
    MethodMatchers.Builder startWithParameters(Predicate<Type>... parametersType);

  }

}
