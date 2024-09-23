using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.CategoryModelViews;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface ICategoryService
    {
        Task<IEnumerable<CategoryModel>> GetCategory(string? id);
        Task<Category> CreateCategory(CategoryModel CategoryModel);
        Task<Category> UpdateCategory(string id, CategoryModel CategoryModel);
        Task<Category> DeleteCategory(object id);
        Task<BasePaginatedList<Category>> PagingCategory(int page, int pageSize);
    }
}
